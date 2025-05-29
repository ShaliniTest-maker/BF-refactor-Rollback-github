"""
Performance testing utilities implementing pytest-benchmark 5.1.0 integration for Flask application
performance validation against Node.js baseline metrics during the migration process.

This module provides comprehensive benchmarking infrastructure ensuring response time equivalence,
memory usage validation, and performance regression detection as specified in Sections 2.4.2, 
2.4.3, 4.7.1, and 5.3.3 of the technical specification.

Key Features:
- pytest-benchmark 5.1.0 fixtures for API response time measurement
- Performance comparison utilities for Node.js baseline validation  
- Memory usage profiling utilities for Flask application resource consumption analysis
- Database query performance benchmarking with SQLAlchemy optimization
- Concurrent user load testing utilities for scalability validation
- Performance regression detection utilities with automated threshold validation

Dependencies:
- pytest-benchmark 5.1.0: Performance benchmarking and regression detection
- Flask 3.1.1: Application performance testing and metrics collection
- Flask-SQLAlchemy 3.1.1: Database query performance optimization and profiling
- psutil: System resource monitoring and memory usage tracking
- concurrent.futures: Concurrent user load testing and scalability validation
"""

import time
import json
import statistics
import concurrent.futures
import threading
import psutil
import gc
from typing import Dict, List, Any, Callable, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from contextlib import contextmanager
from unittest.mock import Mock, patch
import uuid
import os

# Flask and testing imports
import pytest
from flask import Flask, request, g
from flask.testing import FlaskClient
from flask_sqlalchemy import SQLAlchemy

# Performance monitoring imports
try:
    import memory_profiler
    MEMORY_PROFILER_AVAILABLE = True
except ImportError:
    MEMORY_PROFILER_AVAILABLE = False

try:
    import line_profiler
    LINE_PROFILER_AVAILABLE = True
except ImportError:
    LINE_PROFILER_AVAILABLE = False

# Application imports
try:
    from src.models import db
    from src.services import BaseService
    from tests.conftest import MockUser, MockAuth0Client
except ImportError:
    # Handle case where modules don't exist yet during development
    db = None
    BaseService = None
    MockUser = None
    MockAuth0Client = None


# ================================
# Performance Configuration
# ================================

@dataclass
class PerformanceThresholds:
    """
    Performance threshold configuration for automated validation against
    Node.js baseline metrics per Section 2.4.2 requirements.
    
    These thresholds ensure equivalent or improved performance metrics
    during the Flask migration process with comprehensive SLA compliance.
    """
    
    # API Response Time Thresholds (milliseconds)
    api_response_time_p50: float = 100.0  # 50th percentile
    api_response_time_p95: float = 250.0  # 95th percentile  
    api_response_time_p99: float = 500.0  # 99th percentile
    api_response_time_max: float = 1000.0  # Maximum acceptable
    
    # Database Query Performance Thresholds (milliseconds)
    db_query_simple_select: float = 10.0   # Simple SELECT queries
    db_query_complex_join: float = 50.0    # Multi-table JOINs
    db_query_aggregation: float = 100.0    # Aggregation queries
    db_query_transaction: float = 200.0    # Transaction processing
    
    # Memory Usage Thresholds (MB)
    memory_base_usage: float = 50.0        # Base Flask app memory
    memory_per_request: float = 5.0        # Memory per concurrent request
    memory_max_growth: float = 200.0       # Maximum memory growth
    memory_leak_threshold: float = 10.0    # Memory leak detection
    
    # Concurrency Performance Thresholds
    concurrent_users_min: int = 50         # Minimum concurrent users
    concurrent_users_target: int = 100     # Target concurrent users
    concurrent_users_max: int = 200        # Maximum concurrent users
    concurrent_throughput_min: float = 100.0  # Requests per second
    
    # Performance Regression Thresholds (percentage)
    regression_warning: float = 10.0       # Warning threshold
    regression_critical: float = 25.0      # Critical threshold
    improvement_target: float = 5.0        # Improvement target


@dataclass
class BenchmarkResult:
    """
    Comprehensive benchmark result data structure for performance
    metrics collection and analysis during Flask migration testing.
    """
    
    name: str
    start_time: datetime
    end_time: datetime
    duration_ms: float
    memory_usage_mb: float
    cpu_usage_percent: float
    status: str = "success"
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        """Get duration in seconds"""
        return self.duration_ms / 1000.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert benchmark result to dictionary for serialization"""
        return {
            'name': self.name,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_ms': self.duration_ms,
            'duration_seconds': self.duration_seconds,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'status': self.status,
            'error_message': self.error_message,
            'metadata': self.metadata
        }


@dataclass 
class PerformanceReport:
    """
    Comprehensive performance analysis report comparing Flask implementation
    against Node.js baseline metrics with regression detection capabilities.
    """
    
    test_name: str
    benchmark_results: List[BenchmarkResult]
    baseline_comparison: Dict[str, float] = field(default_factory=dict)
    performance_score: float = 0.0
    regression_detected: bool = False
    recommendations: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    def calculate_statistics(self) -> Dict[str, Any]:
        """Calculate comprehensive performance statistics"""
        if not self.benchmark_results:
            return {}
        
        durations = [r.duration_ms for r in self.benchmark_results if r.status == "success"]
        memory_usage = [r.memory_usage_mb for r in self.benchmark_results if r.status == "success"]
        
        if not durations:
            return {'error': 'No successful benchmark results'}
        
        return {
            'response_time': {
                'mean': statistics.mean(durations),
                'median': statistics.median(durations),
                'p95': self._percentile(durations, 95),
                'p99': self._percentile(durations, 99),
                'min': min(durations),
                'max': max(durations),
                'std_dev': statistics.stdev(durations) if len(durations) > 1 else 0
            },
            'memory_usage': {
                'mean': statistics.mean(memory_usage),
                'median': statistics.median(memory_usage), 
                'max': max(memory_usage),
                'min': min(memory_usage)
            },
            'success_rate': len(durations) / len(self.benchmark_results) * 100,
            'error_count': len([r for r in self.benchmark_results if r.status != "success"])
        }
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile value from data list"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]


# ================================
# Performance Monitoring Utilities  
# ================================

class PerformanceMonitor:
    """
    Comprehensive performance monitoring utility providing real-time
    metrics collection for Flask application performance validation.
    
    This class implements monitoring capabilities specified in Section 4.7.1
    for pytest-benchmark integration and baseline comparison analysis.
    """
    
    def __init__(self, thresholds: PerformanceThresholds = None):
        self.thresholds = thresholds or PerformanceThresholds()
        self.current_process = psutil.Process()
        self.baseline_metrics = {}
        self.monitoring_data = []
        self._monitoring_active = False
        
    @contextmanager
    def monitor_performance(self, operation_name: str, **metadata):
        """
        Context manager for comprehensive performance monitoring during
        specific operations with automatic metrics collection and validation.
        
        Args:
            operation_name: Name of the operation being monitored
            **metadata: Additional metadata for performance context
            
        Yields:
            BenchmarkResult: Performance metrics for the monitored operation
        """
        # Force garbage collection before monitoring
        gc.collect()
        
        # Capture initial system state
        start_time = datetime.utcnow()
        start_memory = self.current_process.memory_info().rss / 1024 / 1024  # MB
        start_cpu_time = self.current_process.cpu_times().user
        
        error_message = None
        status = "success"
        
        try:
            yield
        except Exception as e:
            error_message = str(e)
            status = "error"
            raise
        finally:
            # Capture final system state
            end_time = datetime.utcnow()
            end_memory = self.current_process.memory_info().rss / 1024 / 1024  # MB
            end_cpu_time = self.current_process.cpu_times().user
            
            # Calculate performance metrics
            duration_ms = (end_time - start_time).total_seconds() * 1000
            memory_usage_mb = max(end_memory, start_memory)  # Peak memory usage
            cpu_usage_percent = (end_cpu_time - start_cpu_time) * 100
            
            # Create benchmark result
            result = BenchmarkResult(
                name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                memory_usage_mb=memory_usage_mb,
                cpu_usage_percent=cpu_usage_percent,
                status=status,
                error_message=error_message,
                metadata=metadata
            )
            
            self.monitoring_data.append(result)
            return result
    
    def start_continuous_monitoring(self, interval: float = 0.1):
        """
        Start continuous system monitoring for long-running performance tests
        with configurable sampling interval for detailed analysis.
        
        Args:
            interval: Monitoring sample interval in seconds
        """
        self._monitoring_active = True
        
        def monitor_loop():
            while self._monitoring_active:
                timestamp = datetime.utcnow()
                memory_mb = self.current_process.memory_info().rss / 1024 / 1024
                cpu_percent = self.current_process.cpu_percent()
                
                self.monitoring_data.append({
                    'timestamp': timestamp,
                    'memory_mb': memory_mb,
                    'cpu_percent': cpu_percent,
                    'type': 'continuous_sample'
                })
                
                time.sleep(interval)
        
        # Start monitoring in separate thread
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        return monitor_thread
    
    def stop_continuous_monitoring(self):
        """Stop continuous monitoring and return collected metrics"""
        self._monitoring_active = False
        continuous_data = [
            item for item in self.monitoring_data 
            if isinstance(item, dict) and item.get('type') == 'continuous_sample'
        ]
        return continuous_data
    
    def validate_against_thresholds(self, result: BenchmarkResult) -> Dict[str, Any]:
        """
        Validate benchmark results against performance thresholds with
        detailed analysis and regression detection capabilities.
        
        Args:
            result: Benchmark result to validate
            
        Returns:
            Dict containing validation results and recommendations
        """
        validation = {
            'passed': True,
            'warnings': [],
            'failures': [],
            'recommendations': []
        }
        
        # API Response Time Validation
        if 'api' in result.name.lower():
            if result.duration_ms > self.thresholds.api_response_time_max:
                validation['failures'].append(
                    f"API response time {result.duration_ms}ms exceeds maximum threshold "
                    f"{self.thresholds.api_response_time_max}ms"
                )
                validation['passed'] = False
            elif result.duration_ms > self.thresholds.api_response_time_p95:
                validation['warnings'].append(
                    f"API response time {result.duration_ms}ms exceeds P95 threshold "
                    f"{self.thresholds.api_response_time_p95}ms"
                )
        
        # Database Query Performance Validation
        if 'database' in result.name.lower() or 'query' in result.name.lower():
            if 'simple' in result.name.lower():
                threshold = self.thresholds.db_query_simple_select
            elif 'join' in result.name.lower():
                threshold = self.thresholds.db_query_complex_join
            elif 'aggregation' in result.name.lower():
                threshold = self.thresholds.db_query_aggregation
            else:
                threshold = self.thresholds.db_query_transaction
                
            if result.duration_ms > threshold:
                validation['failures'].append(
                    f"Database query time {result.duration_ms}ms exceeds threshold {threshold}ms"
                )
                validation['passed'] = False
        
        # Memory Usage Validation
        if result.memory_usage_mb > self.thresholds.memory_max_growth:
            validation['failures'].append(
                f"Memory usage {result.memory_usage_mb}MB exceeds maximum threshold "
                f"{self.thresholds.memory_max_growth}MB"
            )
            validation['passed'] = False
        
        # Generate Performance Recommendations
        if result.duration_ms > self.thresholds.api_response_time_p50:
            validation['recommendations'].append(
                "Consider implementing response caching for improved performance"
            )
        
        if result.memory_usage_mb > self.thresholds.memory_base_usage * 2:
            validation['recommendations'].append(
                "High memory usage detected - consider memory optimization"
            )
        
        return validation
    
    def compare_with_baseline(self, current_metrics: Dict[str, float], 
                             baseline_metrics: Dict[str, float]) -> Dict[str, Any]:
        """
        Compare current performance metrics with Node.js baseline for
        regression detection and performance validation per Section 4.7.2.
        
        Args:
            current_metrics: Current Flask application metrics
            baseline_metrics: Node.js baseline metrics for comparison
            
        Returns:
            Detailed comparison analysis with regression detection
        """
        comparison = {
            'performance_delta': {},
            'regression_detected': False,
            'improvements': [],
            'regressions': [],
            'overall_score': 100.0
        }
        
        for metric_name, current_value in current_metrics.items():
            if metric_name not in baseline_metrics:
                continue
                
            baseline_value = baseline_metrics[metric_name]
            if baseline_value == 0:
                continue
                
            # Calculate percentage change
            delta_percent = ((current_value - baseline_value) / baseline_value) * 100
            comparison['performance_delta'][metric_name] = {
                'current': current_value,
                'baseline': baseline_value,
                'delta_percent': delta_percent,
                'delta_absolute': current_value - baseline_value
            }
            
            # Detect regressions and improvements
            if delta_percent > self.thresholds.regression_critical:
                comparison['regressions'].append({
                    'metric': metric_name,
                    'severity': 'critical',
                    'delta_percent': delta_percent
                })
                comparison['regression_detected'] = True
                comparison['overall_score'] -= 25
            elif delta_percent > self.thresholds.regression_warning:
                comparison['regressions'].append({
                    'metric': metric_name, 
                    'severity': 'warning',
                    'delta_percent': delta_percent
                })
                comparison['overall_score'] -= 10
            elif delta_percent < -self.thresholds.improvement_target:
                comparison['improvements'].append({
                    'metric': metric_name,
                    'delta_percent': delta_percent
                })
                comparison['overall_score'] += 5
        
        return comparison


# ================================
# API Performance Testing Utilities
# ================================

class APIPerformanceTester:
    """
    Specialized API performance testing utility for comprehensive
    Flask endpoint benchmarking against Node.js baseline metrics.
    
    This class implements API performance validation requirements
    specified in Section 2.4.2 with pytest-benchmark integration.
    """
    
    def __init__(self, app: Flask, client: FlaskClient, monitor: PerformanceMonitor):
        self.app = app
        self.client = client
        self.monitor = monitor
        self.endpoint_results = {}
        
    def benchmark_endpoint(self, method: str, url: str, 
                          data: Dict = None, headers: Dict = None,
                          iterations: int = 10, **kwargs) -> PerformanceReport:
        """
        Comprehensive endpoint performance benchmarking with detailed
        metrics collection and statistical analysis capabilities.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Endpoint URL to benchmark
            data: Request data for POST/PUT requests
            headers: HTTP headers for authentication
            iterations: Number of benchmark iterations
            **kwargs: Additional request parameters
            
        Returns:
            Detailed performance report with statistical analysis
        """
        results = []
        endpoint_name = f"{method}_{url.replace('/', '_')}"
        
        # Warm-up requests to initialize Flask application state
        for _ in range(3):
            try:
                self._make_request(method, url, data, headers, **kwargs)
            except Exception:
                pass  # Ignore warm-up errors
        
        # Execute benchmark iterations
        for iteration in range(iterations):
            with self.monitor.monitor_performance(
                f"api_endpoint_{endpoint_name}_iter_{iteration}",
                method=method,
                url=url,
                iteration=iteration
            ) as monitor_context:
                try:
                    response = self._make_request(method, url, data, headers, **kwargs)
                    
                    # Validate response for functional correctness
                    assert response.status_code < 500, \
                        f"Server error: {response.status_code}"
                    
                    # Record successful request
                    results.append(monitor_context)
                    
                except Exception as e:
                    # Record failed request for analysis
                    monitor_context.status = "error"
                    monitor_context.error_message = str(e)
                    results.append(monitor_context)
        
        # Generate comprehensive performance report
        report = PerformanceReport(
            test_name=f"API Endpoint: {method} {url}",
            benchmark_results=results
        )
        
        # Store results for cross-endpoint analysis
        self.endpoint_results[endpoint_name] = report
        
        return report
    
    def _make_request(self, method: str, url: str, data: Dict = None, 
                     headers: Dict = None, **kwargs):
        """Execute HTTP request with proper error handling"""
        method = method.upper()
        
        if method == 'GET':
            return self.client.get(url, headers=headers, **kwargs)
        elif method == 'POST':
            return self.client.post(url, json=data, headers=headers, **kwargs)
        elif method == 'PUT':
            return self.client.put(url, json=data, headers=headers, **kwargs)
        elif method == 'DELETE':
            return self.client.delete(url, headers=headers, **kwargs)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")
    
    def benchmark_crud_operations(self, base_url: str, test_data: Dict,
                                 headers: Dict = None) -> Dict[str, PerformanceReport]:
        """
        Comprehensive CRUD operations benchmarking for complete
        API functionality validation with performance metrics.
        
        Args:
            base_url: Base URL for CRUD operations (e.g., '/api/users')
            test_data: Test data for CREATE and UPDATE operations
            headers: Authentication headers
            
        Returns:
            Dictionary of performance reports for each CRUD operation
        """
        crud_results = {}
        
        # CREATE operation benchmark
        create_report = self.benchmark_endpoint(
            'POST', base_url, data=test_data, headers=headers
        )
        crud_results['create'] = create_report
        
        # READ operations benchmark
        read_list_report = self.benchmark_endpoint(
            'GET', base_url, headers=headers
        )
        crud_results['read_list'] = read_list_report
        
        read_detail_report = self.benchmark_endpoint(
            'GET', f"{base_url}/1", headers=headers
        )
        crud_results['read_detail'] = read_detail_report
        
        # UPDATE operation benchmark
        update_data = {**test_data, 'updated_field': 'updated_value'}
        update_report = self.benchmark_endpoint(
            'PUT', f"{base_url}/1", data=update_data, headers=headers
        )
        crud_results['update'] = update_report
        
        # DELETE operation benchmark
        delete_report = self.benchmark_endpoint(
            'DELETE', f"{base_url}/1", headers=headers
        )
        crud_results['delete'] = delete_report
        
        return crud_results
    
    def benchmark_with_authentication(self, endpoints: List[Tuple[str, str]], 
                                    auth_scenarios: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Authentication-aware endpoint benchmarking for security
        performance validation and access control testing.
        
        Args:
            endpoints: List of (method, url) tuples to benchmark
            auth_scenarios: Dictionary of authentication scenarios
            
        Returns:
            Comprehensive authentication performance analysis
        """
        auth_results = {}
        
        for scenario_name, auth_config in auth_scenarios.items():
            scenario_results = {}
            headers = auth_config.get('headers', {})
            
            for method, url in endpoints:
                endpoint_key = f"{method}_{url}"
                
                try:
                    report = self.benchmark_endpoint(
                        method, url, headers=headers,
                        data=auth_config.get('data')
                    )
                    scenario_results[endpoint_key] = report
                    
                except Exception as e:
                    scenario_results[endpoint_key] = {
                        'error': str(e),
                        'status': 'failed'
                    }
            
            auth_results[scenario_name] = scenario_results
        
        return auth_results


# ================================
# Database Performance Testing
# ================================

class DatabasePerformanceTester:
    """
    Specialized database performance testing utility for Flask-SQLAlchemy
    query optimization and performance validation per Section 5.3.3.
    
    This class provides comprehensive database benchmarking capabilities
    ensuring equivalent performance to Node.js MongoDB operations.
    """
    
    def __init__(self, db_session, monitor: PerformanceMonitor):
        self.db_session = db_session
        self.monitor = monitor
        self.query_results = {}
        
    def benchmark_query(self, query_func: Callable, query_name: str,
                       iterations: int = 10, **kwargs) -> PerformanceReport:
        """
        Comprehensive database query benchmarking with detailed
        performance analysis and optimization recommendations.
        
        Args:
            query_func: Database query function to benchmark
            query_name: Descriptive name for the query
            iterations: Number of benchmark iterations
            **kwargs: Query parameters
            
        Returns:
            Detailed query performance report
        """
        results = []
        
        # Warm-up queries to initialize connection pool
        for _ in range(3):
            try:
                query_func(**kwargs)
                self.db_session.rollback()  # Ensure clean state
            except Exception:
                pass
        
        # Execute benchmark iterations
        for iteration in range(iterations):
            with self.monitor.monitor_performance(
                f"database_query_{query_name}_iter_{iteration}",
                query_name=query_name,
                iteration=iteration,
                **kwargs
            ) as monitor_context:
                try:
                    # Execute query with timing
                    result = query_func(**kwargs)
                    
                    # Record query execution metadata
                    monitor_context.metadata.update({
                        'result_count': len(result) if hasattr(result, '__len__') else 1,
                        'query_type': self._classify_query(query_name)
                    })
                    
                    # Ensure transaction cleanup
                    self.db_session.rollback()
                    results.append(monitor_context)
                    
                except Exception as e:
                    self.db_session.rollback()
                    monitor_context.status = "error"
                    monitor_context.error_message = str(e)
                    results.append(monitor_context)
        
        # Generate performance report
        report = PerformanceReport(
            test_name=f"Database Query: {query_name}",
            benchmark_results=results
        )
        
        self.query_results[query_name] = report
        return report
    
    def _classify_query(self, query_name: str) -> str:
        """Classify query type for performance threshold selection"""
        name_lower = query_name.lower()
        
        if 'join' in name_lower:
            return 'complex_join'
        elif 'aggregate' in name_lower or 'count' in name_lower or 'sum' in name_lower:
            return 'aggregation'
        elif 'transaction' in name_lower or 'bulk' in name_lower:
            return 'transaction'
        else:
            return 'simple_select'
    
    def benchmark_model_operations(self, model_class, test_data: Dict,
                                 operations: List[str] = None) -> Dict[str, PerformanceReport]:
        """
        Comprehensive model CRUD operations benchmarking for ORM
        performance validation and optimization analysis.
        
        Args:
            model_class: SQLAlchemy model class to benchmark
            test_data: Test data for model operations
            operations: List of operations to benchmark
            
        Returns:
            Dictionary of performance reports for each operation
        """
        if operations is None:
            operations = ['create', 'read', 'update', 'delete', 'bulk_create']
        
        operation_results = {}
        model_name = model_class.__name__
        
        for operation in operations:
            if operation == 'create':
                def create_operation():
                    instance = model_class(**test_data)
                    self.db_session.add(instance)
                    self.db_session.flush()
                    return instance
                
                report = self.benchmark_query(
                    create_operation, 
                    f"{model_name}_create"
                )
                operation_results['create'] = report
                
            elif operation == 'read':
                # Create test instance first
                test_instance = model_class(**test_data)
                self.db_session.add(test_instance)
                self.db_session.flush()
                instance_id = test_instance.id
                self.db_session.rollback()
                
                def read_operation():
                    return self.db_session.query(model_class).filter(
                        model_class.id == instance_id
                    ).first()
                
                report = self.benchmark_query(
                    read_operation,
                    f"{model_name}_read"
                )
                operation_results['read'] = report
                
            elif operation == 'update':
                def update_operation():
                    instance = self.db_session.query(model_class).first()
                    if instance:
                        for key, value in test_data.items():
                            if hasattr(instance, key):
                                setattr(instance, key, f"updated_{value}")
                        self.db_session.flush()
                    return instance
                
                report = self.benchmark_query(
                    update_operation,
                    f"{model_name}_update"
                )
                operation_results['update'] = report
                
            elif operation == 'delete':
                def delete_operation():
                    instance = self.db_session.query(model_class).first()
                    if instance:
                        self.db_session.delete(instance)
                        self.db_session.flush()
                    return instance
                
                report = self.benchmark_query(
                    delete_operation,
                    f"{model_name}_delete"
                )
                operation_results['delete'] = report
                
            elif operation == 'bulk_create':
                def bulk_create_operation():
                    instances = []
                    for i in range(10):
                        data_copy = test_data.copy()
                        data_copy.update({'bulk_index': i})
                        instances.append(model_class(**data_copy))
                    
                    self.db_session.add_all(instances)
                    self.db_session.flush()
                    return instances
                
                report = self.benchmark_query(
                    bulk_create_operation,
                    f"{model_name}_bulk_create"
                )
                operation_results['bulk_create'] = report
        
        return operation_results
    
    def benchmark_relationship_queries(self, relationships: Dict[str, Callable]) -> Dict[str, PerformanceReport]:
        """
        Relationship query performance benchmarking for complex
        data relationships and join operation optimization.
        
        Args:
            relationships: Dictionary of relationship queries to benchmark
            
        Returns:
            Performance reports for each relationship query
        """
        relationship_results = {}
        
        for relationship_name, query_func in relationships.items():
            report = self.benchmark_query(
                query_func,
                f"relationship_{relationship_name}",
                iterations=5  # Fewer iterations for complex queries
            )
            relationship_results[relationship_name] = report
        
        return relationship_results


# ================================
# Concurrent Load Testing
# ================================

class ConcurrentLoadTester:
    """
    Comprehensive concurrent user load testing utility for Flask application
    scalability validation per Section 2.4.3 requirements.
    
    This class implements concurrent user simulation and performance
    validation ensuring equivalent scalability to Node.js implementation.
    """
    
    def __init__(self, app: Flask, monitor: PerformanceMonitor):
        self.app = app
        self.monitor = monitor
        self.load_test_results = {}
        
    def simulate_concurrent_users(self, user_count: int, duration_seconds: int,
                                 test_scenario: Callable, **scenario_kwargs) -> Dict[str, Any]:
        """
        Simulate concurrent user load with comprehensive performance
        monitoring and scalability analysis capabilities.
        
        Args:
            user_count: Number of concurrent users to simulate
            duration_seconds: Test duration in seconds
            test_scenario: Function representing user behavior
            **scenario_kwargs: Parameters for test scenario
            
        Returns:
            Comprehensive load testing results and analysis
        """
        results = {
            'user_count': user_count,
            'duration_seconds': duration_seconds,
            'start_time': datetime.utcnow(),
            'end_time': None,
            'user_results': [],
            'system_metrics': [],
            'performance_summary': {}
        }
        
        # Start continuous system monitoring
        monitor_thread = self.monitor.start_continuous_monitoring(interval=0.5)
        
        # Create thread pool for concurrent user simulation
        with concurrent.futures.ThreadPoolExecutor(max_workers=user_count) as executor:
            # Submit user simulation tasks
            future_to_user = {}
            
            for user_id in range(user_count):
                future = executor.submit(
                    self._simulate_single_user,
                    user_id=user_id,
                    duration_seconds=duration_seconds,
                    test_scenario=test_scenario,
                    **scenario_kwargs
                )
                future_to_user[future] = user_id
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_user, timeout=duration_seconds + 30):
                user_id = future_to_user[future]
                try:
                    user_result = future.result()
                    user_result['user_id'] = user_id
                    results['user_results'].append(user_result)
                except Exception as e:
                    results['user_results'].append({
                        'user_id': user_id,
                        'status': 'error',
                        'error_message': str(e),
                        'requests_completed': 0
                    })
        
        # Stop monitoring and collect system metrics
        system_metrics = self.monitor.stop_continuous_monitoring()
        results['system_metrics'] = system_metrics
        results['end_time'] = datetime.utcnow()
        
        # Calculate performance summary
        results['performance_summary'] = self._calculate_load_test_summary(results)
        
        return results
    
    def _simulate_single_user(self, user_id: int, duration_seconds: int,
                             test_scenario: Callable, **scenario_kwargs) -> Dict[str, Any]:
        """
        Simulate individual user behavior with request timing and error tracking
        """
        user_result = {
            'user_id': user_id,
            'start_time': datetime.utcnow(),
            'end_time': None,
            'requests_completed': 0,
            'requests_failed': 0,
            'total_response_time': 0.0,
            'response_times': [],
            'errors': []
        }
        
        end_time = datetime.utcnow() + timedelta(seconds=duration_seconds)
        
        # Create isolated Flask test client for this user
        with self.app.test_client() as client:
            while datetime.utcnow() < end_time:
                try:
                    request_start = time.time()
                    
                    # Execute user scenario
                    scenario_result = test_scenario(
                        client=client,
                        user_id=user_id,
                        **scenario_kwargs
                    )
                    
                    request_duration = (time.time() - request_start) * 1000  # ms
                    user_result['response_times'].append(request_duration)
                    user_result['total_response_time'] += request_duration
                    user_result['requests_completed'] += 1
                    
                    # Brief pause between requests to simulate realistic user behavior
                    time.sleep(0.1)
                    
                except Exception as e:
                    user_result['requests_failed'] += 1
                    user_result['errors'].append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'error': str(e)
                    })
                    
                    # Continue testing despite errors
                    time.sleep(0.5)
        
        user_result['end_time'] = datetime.utcnow()
        return user_result
    
    def _calculate_load_test_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive load test performance summary"""
        user_results = results['user_results']
        successful_users = [r for r in user_results if r.get('status') != 'error']
        
        if not successful_users:
            return {'error': 'No successful user simulations'}
        
        # Calculate aggregate metrics
        total_requests = sum(r['requests_completed'] for r in successful_users)
        total_failures = sum(r['requests_failed'] for r in successful_users)
        all_response_times = []
        
        for user_result in successful_users:
            all_response_times.extend(user_result.get('response_times', []))
        
        # Calculate throughput
        actual_duration = (results['end_time'] - results['start_time']).total_seconds()
        throughput_rps = total_requests / actual_duration if actual_duration > 0 else 0
        
        summary = {
            'total_requests': total_requests,
            'total_failures': total_failures,
            'success_rate': (total_requests - total_failures) / total_requests * 100 if total_requests > 0 else 0,
            'throughput_rps': throughput_rps,
            'actual_duration_seconds': actual_duration,
            'average_users_active': len(successful_users)
        }
        
        # Response time statistics
        if all_response_times:
            summary['response_times'] = {
                'mean': statistics.mean(all_response_times),
                'median': statistics.median(all_response_times),
                'p95': self._percentile(all_response_times, 95),
                'p99': self._percentile(all_response_times, 99),
                'min': min(all_response_times),
                'max': max(all_response_times)
            }
        
        # System resource utilization from monitoring data
        system_metrics = results.get('system_metrics', [])
        if system_metrics:
            memory_values = [m['memory_mb'] for m in system_metrics]
            cpu_values = [m['cpu_percent'] for m in system_metrics]
            
            summary['system_utilization'] = {
                'peak_memory_mb': max(memory_values),
                'average_memory_mb': statistics.mean(memory_values),
                'peak_cpu_percent': max(cpu_values),
                'average_cpu_percent': statistics.mean(cpu_values)
            }
        
        return summary
    
    def _percentile(self, data: List[float], percentile: float) -> float:
        """Calculate percentile value from data list"""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * percentile / 100)
        return sorted_data[min(index, len(sorted_data) - 1)]
    
    def stress_test_endpoints(self, endpoints: List[Tuple[str, str]], 
                             max_users: int = 200, ramp_up_time: int = 60) -> Dict[str, Any]:
        """
        Comprehensive stress testing for multiple endpoints with
        gradual user ramp-up and performance degradation analysis.
        
        Args:
            endpoints: List of (method, url) tuples to stress test
            max_users: Maximum number of concurrent users
            ramp_up_time: Time to ramp up to max users
            
        Returns:
            Detailed stress test results and breaking point analysis
        """
        stress_results = {
            'endpoints': endpoints,
            'max_users': max_users,
            'ramp_up_time': ramp_up_time,
            'user_levels': [],
            'breaking_point': None,
            'performance_degradation': []
        }
        
        # Test with increasing user loads
        user_levels = [10, 25, 50, 100, 150, 200]
        user_levels = [level for level in user_levels if level <= max_users]
        
        for user_count in user_levels:
            print(f"Testing with {user_count} concurrent users...")
            
            def multi_endpoint_scenario(client, user_id, **kwargs):
                """Test scenario hitting multiple endpoints randomly"""
                import random
                method, url = random.choice(endpoints)
                
                if method.upper() == 'GET':
                    response = client.get(url)
                elif method.upper() == 'POST':
                    test_data = {'user_id': user_id, 'test_field': f'value_{user_id}'}
                    response = client.post(url, json=test_data)
                else:
                    response = client.get(url)  # Fallback to GET
                
                return response
            
            # Run load test for this user level
            load_result = self.simulate_concurrent_users(
                user_count=user_count,
                duration_seconds=30,  # Shorter duration for stress testing
                test_scenario=multi_endpoint_scenario
            )
            
            # Analyze results for breaking point detection
            summary = load_result['performance_summary']
            user_level_result = {
                'user_count': user_count,
                'throughput_rps': summary.get('throughput_rps', 0),
                'success_rate': summary.get('success_rate', 0),
                'avg_response_time': summary.get('response_times', {}).get('mean', 0),
                'peak_memory_mb': summary.get('system_utilization', {}).get('peak_memory_mb', 0)
            }
            
            stress_results['user_levels'].append(user_level_result)
            
            # Check for breaking point (significant performance degradation)
            if (user_level_result['success_rate'] < 95 or 
                user_level_result['avg_response_time'] > 1000):  # 1 second
                stress_results['breaking_point'] = user_count
                break
        
        return stress_results


# ================================
# Memory Usage Analysis
# ================================

class MemoryProfiler:
    """
    Comprehensive memory usage profiling utility for Flask application
    resource consumption analysis per Section 2.4.2 requirements.
    
    This class provides detailed memory usage monitoring and leak
    detection capabilities for performance validation.
    """
    
    def __init__(self, monitor: PerformanceMonitor):
        self.monitor = monitor
        self.memory_snapshots = []
        self.baseline_memory = None
        
    @contextmanager
    def profile_memory_usage(self, operation_name: str):
        """
        Context manager for detailed memory usage profiling during
        specific operations with leak detection capabilities.
        
        Args:
            operation_name: Name of the operation being profiled
            
        Yields:
            Memory profiling context
        """
        # Force garbage collection and capture baseline
        gc.collect()
        baseline_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
        
        if self.baseline_memory is None:
            self.baseline_memory = baseline_memory
        
        start_time = datetime.utcnow()
        
        try:
            yield self
        finally:
            # Capture final memory state
            gc.collect()
            final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            end_time = datetime.utcnow()
            
            # Record memory snapshot
            snapshot = {
                'operation_name': operation_name,
                'start_time': start_time,
                'end_time': end_time,
                'baseline_memory_mb': baseline_memory,
                'final_memory_mb': final_memory,
                'memory_delta_mb': final_memory - baseline_memory,
                'memory_growth_percent': ((final_memory - self.baseline_memory) / self.baseline_memory) * 100
            }
            
            self.memory_snapshots.append(snapshot)
    
    def detect_memory_leaks(self, iterations: int = 100) -> Dict[str, Any]:
        """
        Memory leak detection through repeated operation execution
        with statistical analysis of memory growth patterns.
        
        Args:
            iterations: Number of iterations for leak detection
            
        Returns:
            Memory leak analysis results
        """
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_measurements = [initial_memory]
        
        # Simulate repeated operations
        for i in range(iterations):
            # Simulate typical Flask request processing
            with self.profile_memory_usage(f"leak_test_iteration_{i}"):
                # Create and destroy some objects to simulate memory usage
                test_data = [{'id': j, 'data': f'test_data_{j}'} for j in range(100)]
                test_dict = {f'key_{j}': f'value_{j}' for j in range(100)}
                
                # Force garbage collection every 10 iterations
                if i % 10 == 0:
                    gc.collect()
            
            current_memory = psutil.Process().memory_info().rss / 1024 / 1024
            memory_measurements.append(current_memory)
        
        # Analyze memory growth pattern
        memory_growth = [
            memory_measurements[i] - initial_memory 
            for i in range(1, len(memory_measurements))
        ]
        
        # Statistical analysis
        if len(memory_growth) > 10:
            # Check for consistent upward trend (potential memory leak)
            recent_growth = memory_growth[-10:]
            average_growth = statistics.mean(recent_growth)
            growth_trend = recent_growth[-1] - recent_growth[0]
            
            leak_detected = (
                average_growth > self.monitor.thresholds.memory_leak_threshold and
                growth_trend > 0
            )
            
            return {
                'leak_detected': leak_detected,
                'initial_memory_mb': initial_memory,
                'final_memory_mb': memory_measurements[-1],
                'total_growth_mb': memory_measurements[-1] - initial_memory,
                'average_growth_per_iteration': average_growth,
                'growth_trend_recent': growth_trend,
                'max_memory_mb': max(memory_measurements),
                'memory_measurements': memory_measurements,
                'analysis': {
                    'severity': 'critical' if leak_detected and average_growth > 20 else 'warning' if leak_detected else 'normal',
                    'recommendation': self._generate_memory_recommendation(leak_detected, average_growth)
                }
            }
        
        return {'error': 'Insufficient data for leak analysis'}
    
    def _generate_memory_recommendation(self, leak_detected: bool, growth_rate: float) -> str:
        """Generate memory optimization recommendations"""
        if not leak_detected:
            return "Memory usage appears stable with no leaks detected."
        
        if growth_rate > 20:
            return "Critical memory leak detected. Review object lifecycle management and consider implementing connection pooling."
        elif growth_rate > 10:
            return "Moderate memory growth detected. Consider implementing garbage collection optimizations and memory profiling."
        else:
            return "Minor memory growth detected. Monitor memory usage patterns and implement periodic cleanup routines."
    
    def analyze_memory_patterns(self) -> Dict[str, Any]:
        """
        Comprehensive memory usage pattern analysis for
        performance optimization recommendations.
        
        Returns:
            Detailed memory usage analysis and recommendations
        """
        if not self.memory_snapshots:
            return {'error': 'No memory snapshots available for analysis'}
        
        # Calculate memory usage statistics
        memory_deltas = [s['memory_delta_mb'] for s in self.memory_snapshots]
        growth_percentages = [s['memory_growth_percent'] for s in self.memory_snapshots]
        
        analysis = {
            'total_snapshots': len(self.memory_snapshots),
            'memory_delta_stats': {
                'mean': statistics.mean(memory_deltas),
                'median': statistics.median(memory_deltas), 
                'max': max(memory_deltas),
                'min': min(memory_deltas),
                'std_dev': statistics.stdev(memory_deltas) if len(memory_deltas) > 1 else 0
            },
            'growth_percentage_stats': {
                'mean': statistics.mean(growth_percentages),
                'median': statistics.median(growth_percentages),
                'max': max(growth_percentages),
                'min': min(growth_percentages)
            },
            'memory_efficiency': {
                'operations_with_growth': len([d for d in memory_deltas if d > 0]),
                'operations_with_reduction': len([d for d in memory_deltas if d < 0]),
                'stable_operations': len([d for d in memory_deltas if abs(d) < 1.0])
            }
        }
        
        # Generate recommendations
        recommendations = []
        
        if analysis['memory_delta_stats']['mean'] > 5.0:
            recommendations.append("High average memory growth per operation detected. Consider implementing object pooling.")
        
        if analysis['memory_delta_stats']['max'] > 50.0:
            recommendations.append("Very high peak memory usage detected. Review memory-intensive operations.")
        
        if analysis['memory_efficiency']['operations_with_growth'] > len(self.memory_snapshots) * 0.8:
            recommendations.append("Majority of operations show memory growth. Implement periodic garbage collection.")
        
        analysis['recommendations'] = recommendations
        return analysis


# ================================
# pytest-benchmark Integration
# ================================

@pytest.fixture
def performance_monitor():
    """
    pytest fixture providing configured PerformanceMonitor instance
    for comprehensive Flask application performance testing.
    
    Returns:
        PerformanceMonitor: Configured performance monitoring utility
    """
    thresholds = PerformanceThresholds()
    return PerformanceMonitor(thresholds)


@pytest.fixture  
def api_performance_tester(app, client, performance_monitor):
    """
    pytest fixture providing API performance testing utility with
    Flask application integration for endpoint benchmarking.
    
    Args:
        app: Flask application instance from conftest.py
        client: Flask test client from conftest.py
        performance_monitor: Performance monitor from performance_monitor fixture
        
    Returns:
        APIPerformanceTester: Configured API performance testing utility
    """
    return APIPerformanceTester(app, client, performance_monitor)


@pytest.fixture
def database_performance_tester(db_session, performance_monitor):
    """
    pytest fixture providing database performance testing utility with
    Flask-SQLAlchemy integration for query optimization analysis.
    
    Args:
        db_session: Database session from conftest.py
        performance_monitor: Performance monitor from performance_monitor fixture
        
    Returns:
        DatabasePerformanceTester: Configured database performance testing utility
    """
    return DatabasePerformanceTester(db_session, performance_monitor)


@pytest.fixture
def concurrent_load_tester(app, performance_monitor):
    """
    pytest fixture providing concurrent load testing utility for
    Flask application scalability validation and stress testing.
    
    Args:
        app: Flask application instance from conftest.py
        performance_monitor: Performance monitor from performance_monitor fixture
        
    Returns:
        ConcurrentLoadTester: Configured concurrent load testing utility
    """
    return ConcurrentLoadTester(app, performance_monitor)


@pytest.fixture
def memory_profiler(performance_monitor):
    """
    pytest fixture providing memory profiling utility for Flask
    application resource consumption analysis and leak detection.
    
    Args:
        performance_monitor: Performance monitor from performance_monitor fixture
        
    Returns:
        MemoryProfiler: Configured memory profiling utility
    """
    return MemoryProfiler(performance_monitor)


# ================================
# Baseline Comparison Utilities
# ================================

class BaselineComparator:
    """
    Node.js baseline comparison utility for performance regression detection
    and migration validation per Section 4.7.2 requirements.
    
    This class provides comprehensive comparison capabilities ensuring
    Flask implementation meets or exceeds Node.js performance metrics.
    """
    
    def __init__(self, baseline_file: str = None):
        self.baseline_file = baseline_file or 'tests/fixtures/nodejs_baseline_metrics.json'
        self.baseline_data = self._load_baseline_data()
        
    def _load_baseline_data(self) -> Dict[str, Any]:
        """Load Node.js baseline metrics from file or use defaults"""
        try:
            if os.path.exists(self.baseline_file):
                with open(self.baseline_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: Could not load baseline data: {e}")
        
        # Default baseline metrics for comparison
        return {
            'api_endpoints': {
                'GET_/api/users': {'response_time_ms': 85, 'memory_mb': 12},
                'POST_/api/users': {'response_time_ms': 120, 'memory_mb': 15},
                'PUT_/api/users': {'response_time_ms': 110, 'memory_mb': 14},
                'DELETE_/api/users': {'response_time_ms': 95, 'memory_mb': 13}
            },
            'database_queries': {
                'user_select': {'query_time_ms': 8},
                'user_insert': {'query_time_ms': 15},
                'user_update': {'query_time_ms': 12},
                'user_delete': {'query_time_ms': 10}
            },
            'system_metrics': {
                'baseline_memory_mb': 45,
                'startup_time_ms': 2500,
                'concurrent_users_supported': 150
            }
        }
    
    def compare_performance_report(self, flask_report: PerformanceReport) -> Dict[str, Any]:
        """
        Compare Flask performance report against Node.js baseline
        with detailed regression analysis and recommendations.
        
        Args:
            flask_report: Flask performance report to compare
            
        Returns:
            Comprehensive baseline comparison analysis
        """
        comparison = {
            'test_name': flask_report.test_name,
            'comparison_timestamp': datetime.utcnow().isoformat(),
            'baseline_available': bool(self.baseline_data),
            'flask_metrics': {},
            'baseline_metrics': {},
            'performance_delta': {},
            'regression_analysis': {},
            'overall_assessment': 'unknown'
        }
        
        # Calculate Flask metrics
        flask_stats = flask_report.calculate_statistics()
        if 'error' not in flask_stats:
            comparison['flask_metrics'] = flask_stats
            
            # Find matching baseline metrics
            baseline_key = self._find_baseline_key(flask_report.test_name)
            if baseline_key:
                baseline_metrics = self.baseline_data.get(baseline_key, {})
                comparison['baseline_metrics'] = baseline_metrics
                
                # Perform detailed comparison
                comparison['performance_delta'] = self._calculate_performance_delta(
                    flask_stats, baseline_metrics
                )
                
                # Analyze regressions
                comparison['regression_analysis'] = self._analyze_regressions(
                    comparison['performance_delta']
                )
                
                # Overall assessment
                comparison['overall_assessment'] = self._determine_overall_assessment(
                    comparison['regression_analysis']
                )
        
        return comparison
    
    def _find_baseline_key(self, test_name: str) -> Optional[str]:
        """Find matching baseline key for test name"""
        test_lower = test_name.lower()
        
        if 'api' in test_lower and 'endpoint' in test_lower:
            return 'api_endpoints'
        elif 'database' in test_lower or 'query' in test_lower:
            return 'database_queries'
        elif 'system' in test_lower or 'memory' in test_lower:
            return 'system_metrics'
        
        return None
    
    def _calculate_performance_delta(self, flask_metrics: Dict, baseline_metrics: Dict) -> Dict[str, Any]:
        """Calculate performance differences between Flask and baseline"""
        delta = {}
        
        # Response time comparison
        if 'response_time' in flask_metrics and 'response_time_ms' in baseline_metrics:
            flask_mean = flask_metrics['response_time']['mean']
            baseline_mean = baseline_metrics['response_time_ms']
            
            delta['response_time'] = {
                'flask_ms': flask_mean,
                'baseline_ms': baseline_mean,
                'difference_ms': flask_mean - baseline_mean,
                'percentage_change': ((flask_mean - baseline_mean) / baseline_mean) * 100
            }
        
        # Memory usage comparison
        if 'memory_usage' in flask_metrics and 'memory_mb' in baseline_metrics:
            flask_memory = flask_metrics['memory_usage']['mean']
            baseline_memory = baseline_metrics['memory_mb']
            
            delta['memory_usage'] = {
                'flask_mb': flask_memory,
                'baseline_mb': baseline_memory,
                'difference_mb': flask_memory - baseline_memory,
                'percentage_change': ((flask_memory - baseline_memory) / baseline_memory) * 100
            }
        
        return delta
    
    def _analyze_regressions(self, performance_delta: Dict) -> Dict[str, Any]:
        """Analyze performance regressions and improvements"""
        analysis = {
            'regressions': [],
            'improvements': [],
            'neutral': [],
            'overall_score': 100
        }
        
        for metric_name, delta_data in performance_delta.items():
            percentage_change = delta_data.get('percentage_change', 0)
            
            if percentage_change > 25:  # 25% regression threshold
                analysis['regressions'].append({
                    'metric': metric_name,
                    'severity': 'critical',
                    'percentage_change': percentage_change
                })
                analysis['overall_score'] -= 30
            elif percentage_change > 10:  # 10% regression threshold
                analysis['regressions'].append({
                    'metric': metric_name,
                    'severity': 'warning', 
                    'percentage_change': percentage_change
                })
                analysis['overall_score'] -= 15
            elif percentage_change < -5:  # 5% improvement
                analysis['improvements'].append({
                    'metric': metric_name,
                    'percentage_change': percentage_change
                })
                analysis['overall_score'] += 10
            else:
                analysis['neutral'].append({
                    'metric': metric_name,
                    'percentage_change': percentage_change
                })
        
        return analysis
    
    def _determine_overall_assessment(self, regression_analysis: Dict) -> str:
        """Determine overall performance assessment"""
        score = regression_analysis['overall_score']
        
        if score >= 90:
            return 'excellent'
        elif score >= 80:
            return 'good'
        elif score >= 70:
            return 'acceptable'
        elif score >= 60:
            return 'needs_improvement'
        else:
            return 'critical_issues'


# ================================
# Performance Test Scenarios
# ================================

def create_api_test_scenario(endpoint_config: Dict[str, Any]) -> Callable:
    """
    Factory function for creating API test scenarios for load testing
    with configurable endpoint behavior and authentication.
    
    Args:
        endpoint_config: Configuration for API test scenario
        
    Returns:
        Callable test scenario function
    """
    def api_scenario(client: FlaskClient, user_id: int, **kwargs):
        """API test scenario implementation"""
        method = endpoint_config.get('method', 'GET').upper()
        url = endpoint_config.get('url', '/api/health')
        headers = endpoint_config.get('headers', {})
        data = endpoint_config.get('data', {})
        
        # Add user-specific data
        if data and 'user_id' not in data:
            data['user_id'] = user_id
        
        if method == 'GET':
            return client.get(url, headers=headers)
        elif method == 'POST':
            return client.post(url, json=data, headers=headers)
        elif method == 'PUT':
            return client.put(url, json=data, headers=headers)
        elif method == 'DELETE':
            return client.delete(url, headers=headers)
        else:
            return client.get(url, headers=headers)
    
    return api_scenario


def create_database_test_scenario(model_operations: List[str]) -> Callable:
    """
    Factory function for creating database test scenarios for
    performance testing with various model operations.
    
    Args:
        model_operations: List of database operations to test
        
    Returns:
        Callable database test scenario function
    """
    def database_scenario(db_session, model_class, **kwargs):
        """Database test scenario implementation"""
        results = []
        
        for operation in model_operations:
            if operation == 'create':
                instance = model_class(name=f"test_{uuid.uuid4().hex[:8]}")
                db_session.add(instance)
                db_session.flush()
                results.append(instance)
                
            elif operation == 'read':
                instance = db_session.query(model_class).first()
                results.append(instance)
                
            elif operation == 'update':
                instance = db_session.query(model_class).first()
                if instance:
                    instance.name = f"updated_{uuid.uuid4().hex[:8]}"
                    db_session.flush()
                    results.append(instance)
                    
            elif operation == 'delete':
                instance = db_session.query(model_class).first()
                if instance:
                    db_session.delete(instance)
                    db_session.flush()
                    results.append(True)
        
        return results
    
    return database_scenario


# ================================
# Regression Detection Utilities
# ================================

class RegressionDetector:
    """
    Automated performance regression detection utility for continuous
    integration and deployment pipeline integration per Section 4.7.1.
    
    This class provides automated threshold validation and regression
    alerting capabilities for Flask migration performance monitoring.
    """
    
    def __init__(self, thresholds: PerformanceThresholds, baseline_comparator: BaselineComparator):
        self.thresholds = thresholds
        self.baseline_comparator = baseline_comparator
        self.regression_history = []
        
    def detect_regressions(self, performance_reports: List[PerformanceReport]) -> Dict[str, Any]:
        """
        Comprehensive regression detection across multiple performance
        reports with trend analysis and alerting capabilities.
        
        Args:
            performance_reports: List of performance reports to analyze
            
        Returns:
            Detailed regression detection results and recommendations
        """
        detection_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'reports_analyzed': len(performance_reports),
            'regressions_detected': [],
            'improvements_detected': [],
            'alerts_generated': [],
            'overall_status': 'unknown'
        }
        
        for report in performance_reports:
            # Compare against baseline
            baseline_comparison = self.baseline_comparator.compare_performance_report(report)
            
            # Analyze regression patterns
            regression_analysis = baseline_comparison.get('regression_analysis', {})
            
            # Check for critical regressions
            for regression in regression_analysis.get('regressions', []):
                if regression['severity'] == 'critical':
                    detection_results['regressions_detected'].append({
                        'test_name': report.test_name,
                        'metric': regression['metric'],
                        'severity': regression['severity'],
                        'percentage_change': regression['percentage_change'],
                        'alert_level': 'critical'
                    })
                    
                    # Generate alert
                    detection_results['alerts_generated'].append({
                        'level': 'critical',
                        'message': f"Critical performance regression detected in {report.test_name}: "
                                 f"{regression['metric']} degraded by {regression['percentage_change']:.1f}%",
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            # Check for improvements
            for improvement in regression_analysis.get('improvements', []):
                detection_results['improvements_detected'].append({
                    'test_name': report.test_name,
                    'metric': improvement['metric'],
                    'percentage_change': improvement['percentage_change']
                })
        
        # Determine overall status
        if detection_results['regressions_detected']:
            critical_regressions = [
                r for r in detection_results['regressions_detected'] 
                if r['severity'] == 'critical'
            ]
            if critical_regressions:
                detection_results['overall_status'] = 'critical_regressions'
            else:
                detection_results['overall_status'] = 'minor_regressions'
        elif detection_results['improvements_detected']:
            detection_results['overall_status'] = 'improved_performance'
        else:
            detection_results['overall_status'] = 'stable_performance'
        
        # Store in regression history
        self.regression_history.append(detection_results)
        
        return detection_results
    
    def generate_performance_dashboard(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance dashboard with historical
        trends and regression patterns for monitoring visualization.
        
        Returns:
            Performance dashboard data for visualization
        """
        dashboard = {
            'generated_at': datetime.utcnow().isoformat(),
            'historical_data': self.regression_history[-10:],  # Last 10 detection runs
            'summary_statistics': {},
            'trend_analysis': {},
            'recommendations': []
        }
        
        if self.regression_history:
            # Calculate summary statistics
            total_regressions = sum(
                len(run['regressions_detected']) for run in self.regression_history
            )
            total_improvements = sum(
                len(run['improvements_detected']) for run in self.regression_history
            )
            
            dashboard['summary_statistics'] = {
                'total_regression_detections': total_regressions,
                'total_improvements_detected': total_improvements,
                'detection_runs': len(self.regression_history),
                'latest_status': self.regression_history[-1]['overall_status']
            }
            
            # Generate recommendations
            if total_regressions > total_improvements:
                dashboard['recommendations'].append(
                    "Performance regression trend detected. Consider performance optimization review."
                )
            elif total_improvements > total_regressions * 2:
                dashboard['recommendations'].append(
                    "Positive performance trend detected. Current optimization strategies are effective."
                )
            else:
                dashboard['recommendations'].append(
                    "Performance appears stable. Continue regular monitoring."
                )
        
        return dashboard


# ================================
# Export Public Interface
# ================================

__all__ = [
    # Core classes
    'PerformanceMonitor',
    'APIPerformanceTester', 
    'DatabasePerformanceTester',
    'ConcurrentLoadTester',
    'MemoryProfiler',
    'BaselineComparator',
    'RegressionDetector',
    
    # Data structures
    'PerformanceThresholds',
    'BenchmarkResult',
    'PerformanceReport',
    
    # Utility functions
    'create_api_test_scenario',
    'create_database_test_scenario',
    
    # pytest fixtures (automatically discovered by pytest)
    'performance_monitor',
    'api_performance_tester',
    'database_performance_tester', 
    'concurrent_load_tester',
    'memory_profiler'
]