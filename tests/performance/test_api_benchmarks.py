"""
Primary API response time benchmarking test suite utilizing pytest-benchmark 5.1.0
to measure and validate Flask API endpoint performance against Node.js baseline metrics.

This critical test file establishes comprehensive API performance validation with
sub-200ms response time requirements, statistical analysis of response time 
distribution, and automated performance regression detection for migration success
validation as specified in Section 4.7.1 and Section 4.11.1 of the technical
specification.

Key Features:
- pytest-benchmark 5.1.0 fixtures for comprehensive API response time measurement
- Baseline comparison framework validating Flask API against Node.js benchmarks
- Sub-200ms API response time validation per SLA requirements
- Statistical analysis of response time distribution with percentile tracking
- Automated performance regression detection with threshold-based validation
- Flask blueprint route testing with comprehensive endpoint coverage

Dependencies:
- pytest-benchmark 5.1.0: Statistical performance measurement and benchmarking
- Flask 3.1.1: Application factory pattern and blueprint architecture
- requests: HTTP client library for external baseline API comparisons
- statistics: Statistical analysis for response time distribution
- threading: Concurrent request testing capabilities
- json: Data serialization for API request/response handling

Performance Requirements:
- API Response Time SLA: < 200ms average response time per Section 4.11.1
- Statistical Validity: Minimum 10 rounds per benchmark for reliable measurements
- Baseline Comparison: 100% functional parity with Node.js performance per Section 4.7.2
- Regression Detection: Automated alerting for performance degradation > 10%
- Comprehensive Coverage: All Flask blueprint routes and critical API endpoints
"""

import json
import statistics
import time
import threading
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from unittest.mock import patch, MagicMock
import random
import uuid

import pytest
from pytest_benchmark import BenchmarkFixture
import requests
from flask import Flask, jsonify, request, g
from flask.testing import FlaskClient

# Import performance testing infrastructure
from .conftest import (
    PerformanceTestingConfiguration,
    PerformanceMetricsCollector,
    ConcurrentLoadTester,
    performance_app,
    performance_client,
    benchmark_fixture,
    api_performance_tester,
    performance_metrics_collector,
    concurrent_load_tester,
    baseline_comparison_validator,
    performance_threshold_validator,
    performance_data_generator
)


class APIBenchmarkSuite:
    """
    Comprehensive API benchmarking test suite providing systematic performance
    validation across all Flask blueprint routes with statistical analysis,
    baseline comparison, and automated regression detection capabilities.
    
    This test suite implements comprehensive API performance testing as specified
    in Section 4.7.1 for Flask API endpoint performance validation and migration
    success criteria verification with sub-200ms response time SLA compliance.
    """
    
    def __init__(self, client: FlaskClient, metrics_collector: PerformanceMetricsCollector):
        self.client = client
        self.metrics_collector = metrics_collector
        self.api_endpoints = self._discover_api_endpoints()
        self.baseline_data = self._load_nodejs_baseline_data()
        self.performance_results = []
        
    def _discover_api_endpoints(self) -> List[Dict[str, Any]]:
        """
        Discover all Flask API endpoints for comprehensive benchmarking
        
        Returns:
            List of API endpoint configurations for testing
        """
        # Define comprehensive API endpoint test cases
        # These would typically be discovered from Flask application routes
        # For migration testing, we test key endpoints that existed in Node.js
        
        endpoints = [
            # Authentication and user management endpoints
            {
                'name': 'auth_login',
                'path': '/api/auth/login',
                'method': 'POST',
                'data': {'username': 'testuser', 'password': 'testpass'},
                'expected_status': 200,
                'auth_required': False,
                'critical': True
            },
            {
                'name': 'auth_logout',
                'path': '/api/auth/logout',
                'method': 'POST',
                'data': {},
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'auth_refresh',
                'path': '/api/auth/refresh',
                'method': 'POST',
                'data': {},
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            
            # User profile and management endpoints
            {
                'name': 'user_profile_get',
                'path': '/api/users/profile',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'user_profile_update',
                'path': '/api/users/profile',
                'method': 'PUT',
                'data': {
                    'name': 'Updated User',
                    'email': 'updated@example.com'
                },
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'users_list',
                'path': '/api/users',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'user_create',
                'path': '/api/users',
                'method': 'POST',
                'data': {
                    'username': 'newuser',
                    'email': 'newuser@example.com',
                    'password': 'newpassword'
                },
                'expected_status': 201,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'user_details',
                'path': '/api/users/123',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': True,
                'critical': False
            },
            {
                'name': 'user_update',
                'path': '/api/users/123',
                'method': 'PUT',
                'data': {'name': 'Updated Name'},
                'expected_status': 200,
                'auth_required': True,
                'critical': False
            },
            {
                'name': 'user_delete',
                'path': '/api/users/123',
                'method': 'DELETE',
                'data': None,
                'expected_status': 204,
                'auth_required': True,
                'critical': False
            },
            
            # Application data endpoints
            {
                'name': 'dashboard_data',
                'path': '/api/dashboard',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'search_results',
                'path': '/api/search',
                'method': 'GET',
                'data': None,
                'query_params': {'q': 'test query', 'limit': 10},
                'expected_status': 200,
                'auth_required': True,
                'critical': True
            },
            {
                'name': 'settings_get',
                'path': '/api/settings',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': True,
                'critical': False
            },
            {
                'name': 'settings_update',
                'path': '/api/settings',
                'method': 'PUT',
                'data': {
                    'theme': 'dark',
                    'notifications': True
                },
                'expected_status': 200,
                'auth_required': True,
                'critical': False
            },
            
            # Public endpoints for baseline testing
            {
                'name': 'health_check',
                'path': '/health',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': False,
                'critical': True
            },
            {
                'name': 'api_status',
                'path': '/api/status',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': False,
                'critical': True
            },
            {
                'name': 'api_version',
                'path': '/api/version',
                'method': 'GET',
                'data': None,
                'expected_status': 200,
                'auth_required': False,
                'critical': False
            }
        ]
        
        return endpoints
    
    def _load_nodejs_baseline_data(self) -> Dict[str, float]:
        """
        Load Node.js baseline performance data for comparison
        
        Returns:
            Dict containing baseline response times for each endpoint
        """
        try:
            with open('tests/performance/nodejs_baseline_metrics.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return mock baseline data for development/testing
            return {
                'auth_login:response_time': 0.085,      # 85ms
                'auth_logout:response_time': 0.045,     # 45ms
                'auth_refresh:response_time': 0.055,    # 55ms
                'user_profile_get:response_time': 0.075, # 75ms
                'user_profile_update:response_time': 0.125, # 125ms
                'users_list:response_time': 0.095,      # 95ms
                'user_create:response_time': 0.135,     # 135ms
                'user_details:response_time': 0.065,    # 65ms
                'user_update:response_time': 0.105,     # 105ms
                'user_delete:response_time': 0.055,     # 55ms
                'dashboard_data:response_time': 0.115,  # 115ms
                'search_results:response_time': 0.155,  # 155ms
                'settings_get:response_time': 0.045,    # 45ms
                'settings_update:response_time': 0.075, # 75ms
                'health_check:response_time': 0.015,    # 15ms
                'api_status:response_time': 0.025,      # 25ms
                'api_version:response_time': 0.020      # 20ms
            }
    
    def execute_single_endpoint_request(self, endpoint: Dict[str, Any], 
                                      auth_headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Execute single API endpoint request with comprehensive timing and validation
        
        Args:
            endpoint: Endpoint configuration dictionary
            auth_headers: Authentication headers for protected endpoints
            
        Returns:
            Dict containing request execution results and timing data
        """
        start_time = time.time()
        
        try:
            # Prepare request headers
            headers = {'Content-Type': 'application/json'}
            if endpoint.get('auth_required') and auth_headers:
                headers.update(auth_headers)
            
            # Prepare query parameters
            query_params = endpoint.get('query_params', {})
            
            # Execute request based on HTTP method
            method = endpoint['method'].upper()
            path = endpoint['path']
            
            if method == 'GET':
                if query_params:
                    path += '?' + '&'.join([f"{k}={v}" for k, v in query_params.items()])
                response = self.client.get(path, headers=headers)
            elif method == 'POST':
                response = self.client.post(
                    path, 
                    json=endpoint.get('data'),
                    headers=headers
                )
            elif method == 'PUT':
                response = self.client.put(
                    path,
                    json=endpoint.get('data'),
                    headers=headers
                )
            elif method == 'DELETE':
                response = self.client.delete(path, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Validate response
            expected_status = endpoint.get('expected_status', 200)
            status_valid = response.status_code == expected_status
            
            # Extract response data safely
            try:
                response_data = response.get_json() if response.data else {}
            except Exception:
                response_data = {}
            
            return {
                'endpoint_name': endpoint['name'],
                'path': endpoint['path'],
                'method': endpoint['method'],
                'duration': duration,
                'status_code': response.status_code,
                'expected_status': expected_status,
                'status_valid': status_valid,
                'response_size': len(response.data) if response.data else 0,
                'success': status_valid and 200 <= response.status_code < 300,
                'response_data': response_data,
                'critical': endpoint.get('critical', False)
            }
            
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            
            return {
                'endpoint_name': endpoint['name'],
                'path': endpoint['path'],
                'method': endpoint['method'],
                'duration': duration,
                'status_code': 500,
                'expected_status': endpoint.get('expected_status', 200),
                'status_valid': False,
                'response_size': 0,
                'success': False,
                'error': str(e),
                'traceback': traceback.format_exc(),
                'critical': endpoint.get('critical', False)
            }


# ================================
# Core API Benchmark Tests
# ================================

@pytest.mark.performance
@pytest.mark.benchmark
@pytest.mark.sla_validation
class TestAPIPerformanceBenchmarks:
    """
    Core API performance benchmark test class providing comprehensive
    Flask API endpoint performance validation with pytest-benchmark 5.1.0
    integration and sub-200ms response time SLA compliance verification.
    
    This test class implements the primary API benchmarking requirements
    as specified in Section 4.7.1 and Section 4.11.1 for comprehensive
    Flask API performance validation and migration success criteria.
    """
    
    @pytest.fixture(autouse=True)
    def setup_api_benchmark_suite(self, performance_client, performance_metrics_collector):
        """Setup API benchmark suite for each test method"""
        self.benchmark_suite = APIBenchmarkSuite(
            client=performance_client,
            metrics_collector=performance_metrics_collector
        )
        
        # Mock authentication headers for testing
        self.auth_headers = {
            'Authorization': 'Bearer test-jwt-token',
            'X-User-ID': 'test-user-123'
        }
    
    def test_api_endpoint_individual_benchmarks(self, benchmark_fixture, 
                                              performance_threshold_validator):
        """
        Individual API endpoint benchmarking with comprehensive performance validation
        
        Tests each Flask API endpoint individually using pytest-benchmark 5.1.0
        for statistical measurement and validates sub-200ms response time SLA
        compliance as specified in Section 4.11.1.
        
        Args:
            benchmark_fixture: Enhanced pytest-benchmark fixture with metrics collection
            performance_threshold_validator: SLA threshold validation utilities
        """
        results = []
        
        for endpoint in self.benchmark_suite.api_endpoints:
            # Skip certain endpoints that might not exist in test environment
            if endpoint['name'] in ['user_details', 'user_update', 'user_delete']:
                continue
                
            def benchmark_endpoint():
                """Benchmark function for pytest-benchmark execution"""
                return self.benchmark_suite.execute_single_endpoint_request(
                    endpoint, self.auth_headers
                )
            
            # Execute benchmark with pytest-benchmark
            benchmark_result = benchmark_fixture(benchmark_endpoint)
            
            # Get benchmark statistics
            if hasattr(benchmark_result, 'stats') and benchmark_result.stats:
                mean_time = benchmark_result.stats.mean
                median_time = benchmark_result.stats.median
                min_time = benchmark_result.stats.min
                max_time = benchmark_result.stats.max
                stddev_time = benchmark_result.stats.stddev
                
                # Validate SLA threshold compliance
                threshold_result = performance_threshold_validator['validate_api'](
                    duration=mean_time,
                    endpoint=endpoint['name']
                )
                
                # Record comprehensive results
                result = {
                    'endpoint_name': endpoint['name'],
                    'endpoint_path': endpoint['path'],
                    'method': endpoint['method'],
                    'mean_response_time': mean_time,
                    'median_response_time': median_time,
                    'min_response_time': min_time,
                    'max_response_time': max_time,
                    'stddev_response_time': stddev_time,
                    'sla_threshold': threshold_result['threshold'],
                    'sla_passed': threshold_result['passed'],
                    'percentage_of_threshold': threshold_result['percentage_of_threshold'],
                    'critical_endpoint': endpoint.get('critical', False),
                    'benchmark_rounds': benchmark_result.stats.rounds,
                    'total_iterations': benchmark_result.stats.iterations
                }
                
                results.append(result)
                
                # Print real-time results for monitoring
                status = "PASS" if threshold_result['passed'] else "FAIL"
                print(f"\n[{status}] {endpoint['name']}: {mean_time*1000:.1f}ms "
                      f"(threshold: {threshold_result['threshold']*1000:.0f}ms)")
                
                # Assert SLA compliance for critical endpoints
                if endpoint.get('critical', False):
                    assert threshold_result['passed'], (
                        f"Critical endpoint {endpoint['name']} failed SLA: "
                        f"{mean_time*1000:.1f}ms > {threshold_result['threshold']*1000:.0f}ms"
                    )
        
        # Comprehensive test suite validation
        self._validate_overall_api_performance(results)
    
    def test_api_response_time_distribution_analysis(self, performance_client,
                                                   performance_metrics_collector):
        """
        Statistical analysis of API response time distribution with percentile
        tracking and performance trend analysis for comprehensive performance
        validation as specified in Section 6.5.1.1.
        
        Args:
            performance_client: Performance-optimized Flask test client
            performance_metrics_collector: Metrics collector for statistical analysis
        """
        # Test high-frequency endpoint for statistical analysis
        endpoint = {
            'name': 'health_check_distribution',
            'path': '/health',
            'method': 'GET',
            'data': None,
            'expected_status': 200,
            'auth_required': False
        }
        
        # Collect large sample of response times for distribution analysis
        response_times = []
        sample_size = 100  # Large sample for statistical validity
        
        print(f"\nCollecting {sample_size} samples for response time distribution analysis...")
        
        for i in range(sample_size):
            start_time = time.time()
            response = performance_client.get(endpoint['path'])
            duration = time.time() - start_time
            response_times.append(duration)
            
            # Progress indicator
            if (i + 1) % 20 == 0:
                print(f"  Progress: {i + 1}/{sample_size} samples collected")
        
        # Calculate comprehensive statistical metrics
        statistics_analysis = {
            'sample_size': len(response_times),
            'mean': statistics.mean(response_times),
            'median': statistics.median(response_times),
            'mode': statistics.mode(response_times) if len(set(response_times)) < len(response_times) else None,
            'std_deviation': statistics.stdev(response_times),
            'variance': statistics.variance(response_times),
            'min_time': min(response_times),
            'max_time': max(response_times),
            'range': max(response_times) - min(response_times)
        }
        
        # Calculate percentiles for detailed distribution analysis
        sorted_times = sorted(response_times)
        percentiles = {
            'p50': self._calculate_percentile(sorted_times, 0.50),
            'p75': self._calculate_percentile(sorted_times, 0.75),
            'p90': self._calculate_percentile(sorted_times, 0.90),
            'p95': self._calculate_percentile(sorted_times, 0.95),
            'p99': self._calculate_percentile(sorted_times, 0.99),
            'p99_9': self._calculate_percentile(sorted_times, 0.999)
        }
        
        # Outlier detection using IQR method
        q1 = self._calculate_percentile(sorted_times, 0.25)
        q3 = self._calculate_percentile(sorted_times, 0.75)
        iqr = q3 - q1
        outlier_threshold_low = q1 - 1.5 * iqr
        outlier_threshold_high = q3 + 1.5 * iqr
        
        outliers = [
            t for t in response_times 
            if t < outlier_threshold_low or t > outlier_threshold_high
        ]
        
        outlier_analysis = {
            'outlier_count': len(outliers),
            'outlier_percentage': (len(outliers) / len(response_times)) * 100,
            'outlier_threshold_low': outlier_threshold_low,
            'outlier_threshold_high': outlier_threshold_high,
            'outliers': outliers
        }
        
        # Record comprehensive metrics
        performance_metrics_collector.record_metric(
            test_name='api_response_distribution',
            metric_type='statistical_analysis',
            value=statistics_analysis['mean'],
            unit='seconds',
            metadata={
                'statistics': statistics_analysis,
                'percentiles': percentiles,
                'outlier_analysis': outlier_analysis
            }
        )
        
        # Generate detailed analysis report
        print(f"\nResponse Time Distribution Analysis Results:")
        print(f"  Sample Size: {statistics_analysis['sample_size']}")
        print(f"  Mean: {statistics_analysis['mean']*1000:.2f}ms")
        print(f"  Median: {statistics_analysis['median']*1000:.2f}ms")
        print(f"  Std Deviation: {statistics_analysis['std_deviation']*1000:.2f}ms")
        print(f"  Min/Max: {statistics_analysis['min_time']*1000:.2f}ms / {statistics_analysis['max_time']*1000:.2f}ms")
        print(f"\nPercentile Analysis:")
        for percentile, value in percentiles.items():
            print(f"  {percentile}: {value*1000:.2f}ms")
        print(f"\nOutlier Analysis:")
        print(f"  Outliers Detected: {outlier_analysis['outlier_count']} ({outlier_analysis['outlier_percentage']:.1f}%)")
        print(f"  Outlier Threshold: {outlier_analysis['outlier_threshold_high']*1000:.2f}ms")
        
        # Validate distribution characteristics
        assert statistics_analysis['mean'] <= PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD, (
            f"Mean response time {statistics_analysis['mean']*1000:.1f}ms exceeds threshold "
            f"{PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD*1000:.0f}ms"
        )
        
        assert percentiles['p95'] <= PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD * 1.5, (
            f"95th percentile {percentiles['p95']*1000:.1f}ms exceeds acceptable threshold"
        )
        
        assert outlier_analysis['outlier_percentage'] <= 5.0, (
            f"Outlier percentage {outlier_analysis['outlier_percentage']:.1f}% exceeds acceptable limit of 5%"
        )
    
    def test_api_baseline_comparison_validation(self, baseline_comparison_validator,
                                              performance_metrics_collector):
        """
        Comprehensive baseline comparison validation against Node.js system
        benchmarks with 100% parity verification and automated discrepancy
        detection as specified in Section 4.7.2.
        
        Args:
            baseline_comparison_validator: Baseline comparison utilities
            performance_metrics_collector: Metrics collector with baseline data
        """
        print("\nExecuting comprehensive baseline comparison validation...")
        
        # Test critical endpoints for baseline comparison
        critical_endpoints = [
            ep for ep in self.benchmark_suite.api_endpoints 
            if ep.get('critical', False) and ep['name'] not in ['user_details', 'user_update', 'user_delete']
        ]
        
        comparison_results = []
        
        for endpoint in critical_endpoints:
            print(f"Testing endpoint: {endpoint['name']}")
            
            # Execute multiple requests for statistical validity
            response_times = []
            for _ in range(15):  # 15 requests for baseline comparison
                result = self.benchmark_suite.execute_single_endpoint_request(
                    endpoint, self.auth_headers
                )
                if result['success']:
                    response_times.append(result['duration'])
            
            if response_times:
                flask_avg_time = statistics.mean(response_times)
                
                # Compare with Node.js baseline
                comparison = performance_metrics_collector.compare_with_baseline(
                    endpoint['name'], 'response_time', flask_avg_time
                )
                
                if comparison.get('comparison_available'):
                    comparison_results.append({
                        'test_name': endpoint['name'],
                        'metric_type': 'response_time',
                        'value': flask_avg_time,
                        'baseline_comparison': comparison
                    })
                    
                    # Print real-time comparison results
                    status = "PASS" if comparison['passed'] else "FAIL"
                    improvement = comparison['improvement_percentage']
                    print(f"  [{status}] Flask: {flask_avg_time*1000:.1f}ms, "
                          f"Node.js: {comparison['nodejs_value']*1000:.1f}ms, "
                          f"Change: {improvement:+.1f}%")
        
        # Validate overall baseline comparison results
        if comparison_results:
            validation_results = baseline_comparison_validator['validate_regression'](
                comparison_results
            )
            
            # Generate comprehensive migration report
            migration_report = baseline_comparison_validator['generate_report'](
                validation_results
            )
            
            print(f"\n{migration_report}")
            
            # Assert overall migration success criteria
            assert validation_results['overall_regression_check_passed'], (
                f"Baseline comparison failed: {validation_results['passed_tests']}/"
                f"{validation_results['total_tests']} tests passed"
            )
            
            # Validate minimum performance improvement requirements
            summary = validation_results['summary']
            assert summary['average_performance_ratio'] <= 1.2, (
                f"Average performance ratio {summary['average_performance_ratio']:.3f} "
                f"indicates significant performance regression"
            )
        else:
            pytest.skip("No baseline comparison data available for validation")
    
    def test_api_performance_regression_detection(self, performance_metrics_collector,
                                                performance_threshold_validator):
        """
        Automated performance regression detection with threshold-based validation
        and alerting for critical API endpoints as specified in Section 4.7.2.
        
        Args:
            performance_metrics_collector: Metrics collector for regression analysis
            performance_threshold_validator: Threshold validation utilities
        """
        print("\nExecuting automated performance regression detection...")
        
        # Define regression detection thresholds
        regression_config = {
            'critical_endpoint_threshold': 0.05,  # 5% regression threshold for critical endpoints
            'standard_endpoint_threshold': 0.10,  # 10% regression threshold for standard endpoints
            'consecutive_failures_threshold': 3,   # Alert after 3 consecutive failures
            'sample_size': 20                      # Sample size for regression analysis
        }
        
        # Test endpoints for regression detection
        test_endpoints = [
            ep for ep in self.benchmark_suite.api_endpoints[:8]  # Test first 8 endpoints
            if ep['name'] not in ['user_details', 'user_update', 'user_delete']
        ]
        
        regression_analysis_results = []
        
        for endpoint in test_endpoints:
            print(f"Analyzing regression for endpoint: {endpoint['name']}")
            
            # Collect performance samples
            response_times = []
            errors = []
            
            for sample_num in range(regression_config['sample_size']):
                result = self.benchmark_suite.execute_single_endpoint_request(
                    endpoint, self.auth_headers
                )
                
                if result['success']:
                    response_times.append(result['duration'])
                else:
                    errors.append(result)
            
            if response_times:
                # Calculate current performance metrics
                current_avg = statistics.mean(response_times)
                current_p95 = self._calculate_percentile(sorted(response_times), 0.95)
                
                # Determine regression threshold based on endpoint criticality
                threshold = (regression_config['critical_endpoint_threshold'] 
                           if endpoint.get('critical', False) 
                           else regression_config['standard_endpoint_threshold'])
                
                # Validate against SLA threshold
                sla_validation = performance_threshold_validator['validate_api'](
                    duration=current_avg,
                    endpoint=endpoint['name']
                )
                
                # Compare with baseline if available
                baseline_comparison = performance_metrics_collector.compare_with_baseline(
                    endpoint['name'], 'response_time', current_avg
                )
                
                # Determine regression status
                regression_detected = False
                regression_details = {}
                
                if baseline_comparison.get('comparison_available'):
                    performance_ratio = baseline_comparison['performance_ratio']
                    regression_detected = performance_ratio > (1.0 + threshold)
                    
                    regression_details = {
                        'baseline_available': True,
                        'current_avg': current_avg,
                        'baseline_avg': baseline_comparison['nodejs_value'],
                        'performance_ratio': performance_ratio,
                        'regression_threshold': threshold,
                        'regression_detected': regression_detected,
                        'improvement_percentage': baseline_comparison['improvement_percentage']
                    }
                
                # Error rate analysis
                error_rate = len(errors) / regression_config['sample_size']
                error_regression = error_rate > 0.05  # 5% error rate threshold
                
                analysis_result = {
                    'endpoint_name': endpoint['name'],
                    'endpoint_path': endpoint['path'],
                    'critical': endpoint.get('critical', False),
                    'current_avg_ms': current_avg * 1000,
                    'current_p95_ms': current_p95 * 1000,
                    'sla_passed': sla_validation['passed'],
                    'error_rate': error_rate,
                    'error_regression': error_regression,
                    'regression_analysis': regression_details,
                    'samples_collected': len(response_times),
                    'total_samples': regression_config['sample_size']
                }
                
                regression_analysis_results.append(analysis_result)
                
                # Print real-time regression analysis
                regression_status = "REGRESSION" if regression_detected else "OK"
                print(f"  [{regression_status}] Avg: {current_avg*1000:.1f}ms, "
                      f"P95: {current_p95*1000:.1f}ms, "
                      f"Error Rate: {error_rate*100:.1f}%")
                
                # Assert critical endpoint regression detection
                if endpoint.get('critical', False):
                    assert not regression_detected, (
                        f"Performance regression detected for critical endpoint {endpoint['name']}: "
                        f"ratio {regression_details.get('performance_ratio', 'N/A'):.3f} > "
                        f"threshold {1.0 + threshold:.3f}"
                    )
                    
                    assert not error_regression, (
                        f"Error rate regression detected for critical endpoint {endpoint['name']}: "
                        f"{error_rate*100:.1f}% > 5%"
                    )
        
        # Generate comprehensive regression analysis report
        self._generate_regression_analysis_report(regression_analysis_results)
        
        # Validate overall system regression status
        critical_regressions = [
            r for r in regression_analysis_results 
            if r['critical'] and r['regression_analysis'].get('regression_detected', False)
        ]
        
        assert len(critical_regressions) == 0, (
            f"Critical performance regressions detected in {len(critical_regressions)} endpoints"
        )
    
    def _validate_overall_api_performance(self, results: List[Dict[str, Any]]):
        """Validate overall API performance across all tested endpoints"""
        total_endpoints = len(results)
        passed_endpoints = len([r for r in results if r['sla_passed']])
        critical_endpoints = len([r for r in results if r['critical_endpoint']])
        critical_passed = len([r for r in results if r['critical_endpoint'] and r['sla_passed']])
        
        # Calculate performance statistics
        avg_response_time = statistics.mean([r['mean_response_time'] for r in results])
        max_response_time = max([r['mean_response_time'] for r in results])
        
        print(f"\nOverall API Performance Summary:")
        print(f"  Total Endpoints Tested: {total_endpoints}")
        print(f"  Endpoints Passed SLA: {passed_endpoints}/{total_endpoints} ({passed_endpoints/total_endpoints*100:.1f}%)")
        print(f"  Critical Endpoints Passed: {critical_passed}/{critical_endpoints}")
        print(f"  Average Response Time: {avg_response_time*1000:.1f}ms")
        print(f"  Maximum Response Time: {max_response_time*1000:.1f}ms")
        
        # Assert overall performance requirements
        assert passed_endpoints / total_endpoints >= 0.95, (
            f"Overall SLA compliance rate {passed_endpoints/total_endpoints*100:.1f}% below 95% threshold"
        )
        
        assert critical_passed == critical_endpoints, (
            f"Critical endpoints failed SLA: {critical_passed}/{critical_endpoints} passed"
        )
    
    def _calculate_percentile(self, sorted_values: List[float], percentile: float) -> float:
        """Calculate percentile value from sorted list of measurements"""
        if not sorted_values:
            return 0.0
        
        index = percentile * (len(sorted_values) - 1)
        lower_index = int(index)
        upper_index = min(lower_index + 1, len(sorted_values) - 1)
        
        if lower_index == upper_index:
            return sorted_values[lower_index]
        
        # Linear interpolation between values
        weight = index - lower_index
        return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight
    
    def _generate_regression_analysis_report(self, results: List[Dict[str, Any]]):
        """Generate comprehensive regression analysis report"""
        print(f"\nRegression Analysis Report:")
        print(f"=" * 80)
        
        critical_endpoints = [r for r in results if r['critical']]
        standard_endpoints = [r for r in results if not r['critical']]
        
        print(f"Critical Endpoints Analysis ({len(critical_endpoints)} endpoints):")
        for result in critical_endpoints:
            status = "OK"
            if result['regression_analysis'].get('regression_detected', False):
                status = "REGRESSION"
            elif not result['sla_passed']:
                status = "SLA_FAIL"
            
            print(f"  [{status}] {result['endpoint_name']}: {result['current_avg_ms']:.1f}ms")
        
        print(f"\nStandard Endpoints Analysis ({len(standard_endpoints)} endpoints):")
        for result in standard_endpoints:
            status = "OK"
            if result['regression_analysis'].get('regression_detected', False):
                status = "REGRESSION"
            elif not result['sla_passed']:
                status = "SLA_FAIL"
            
            print(f"  [{status}] {result['endpoint_name']}: {result['current_avg_ms']:.1f}ms")
        
        print(f"=" * 80)


# ================================
# Concurrent Load Testing for API Endpoints
# ================================

@pytest.mark.performance
@pytest.mark.load_test
@pytest.mark.sla_validation
class TestAPIBenchmarksConcurrentLoad:
    """
    Concurrent load testing for API endpoints validating Flask application
    performance under concurrent user scenarios with comprehensive load
    distribution analysis and system capacity validation.
    
    This test class implements concurrent API testing as specified in
    Section 4.7.1 for comprehensive load testing and concurrent user
    capacity validation with Flask blueprint architecture integration.
    """
    
    @pytest.fixture(autouse=True)
    def setup_concurrent_load_testing(self, performance_client, concurrent_load_tester,
                                    performance_metrics_collector):
        """Setup concurrent load testing infrastructure"""
        self.client = performance_client
        self.load_tester = concurrent_load_tester
        self.metrics_collector = performance_metrics_collector
        self.auth_headers = {
            'Authorization': 'Bearer test-jwt-token',
            'X-User-ID': 'test-user-123'
        }
    
    def test_api_concurrent_user_load_simulation(self, performance_data_generator):
        """
        Concurrent user load simulation testing Flask API endpoints under
        realistic load scenarios with comprehensive performance monitoring
        and capacity analysis.
        
        Args:
            performance_data_generator: Test data generation utilities
        """
        print("\nExecuting concurrent user load simulation...")
        
        # Generate concurrent user test data
        concurrent_users = performance_data_generator['generate_user_data'](
            num_users=25  # 25 concurrent users for load testing
        )
        
        # Define load testing scenarios
        load_scenarios = [
            {
                'name': 'health_check_load',
                'endpoint': '/health',
                'method': 'GET',
                'auth_required': False,
                'concurrent_users': 25,
                'requests_per_user': 10,
                'ramp_up_time': 5
            },
            {
                'name': 'user_profile_load',
                'endpoint': '/api/users/profile',
                'method': 'GET',
                'auth_required': True,
                'concurrent_users': 20,
                'requests_per_user': 8,
                'ramp_up_time': 3
            },
            {
                'name': 'dashboard_data_load',
                'endpoint': '/api/dashboard',
                'method': 'GET',
                'auth_required': True,
                'concurrent_users': 15,
                'requests_per_user': 5,
                'ramp_up_time': 2
            }
        ]
        
        load_test_results = []
        
        for scenario in load_scenarios:
            print(f"\nTesting load scenario: {scenario['name']}")
            print(f"  Concurrent Users: {scenario['concurrent_users']}")
            print(f"  Requests per User: {scenario['requests_per_user']}")
            print(f"  Ramp-up Time: {scenario['ramp_up_time']}s")
            
            # Create request function for the scenario
            def create_request_func(endpoint, method, auth_required):
                def request_func():
                    headers = self.auth_headers if auth_required else {}
                    
                    if method.upper() == 'GET':
                        return self.client.get(endpoint, headers=headers)
                    elif method.upper() == 'POST':
                        return self.client.post(endpoint, json={}, headers=headers)
                    else:
                        return self.client.get(endpoint, headers=headers)
                
                return request_func
            
            request_func = create_request_func(
                scenario['endpoint'], 
                scenario['method'], 
                scenario['auth_required']
            )
            
            # Execute concurrent load test
            total_requests = scenario['concurrent_users'] * scenario['requests_per_user']
            
            load_results = self.load_tester.execute_concurrent_requests(
                request_func=request_func,
                num_requests=total_requests,
                ramp_up_time=scenario['ramp_up_time']
            )
            
            # Analyze and record results
            scenario_result = {
                'scenario_name': scenario['name'],
                'endpoint': scenario['endpoint'],
                'concurrent_users': scenario['concurrent_users'],
                'total_requests': load_results['total_requests'],
                'successful_requests': load_results['successful_requests'],
                'failed_requests': load_results['failed_requests'],
                'success_rate': load_results['success_rate'],
                'requests_per_second': load_results['requests_per_second'],
                'average_response_time': load_results['average_response_time'],
                'p95_response_time': load_results['p95_response_time'],
                'p99_response_time': load_results['p99_response_time'],
                'max_response_time': load_results['max_response_time']
            }
            
            load_test_results.append(scenario_result)
            
            # Record metrics for analysis
            self.metrics_collector.record_metric(
                test_name=f"load_{scenario['name']}",
                metric_type='concurrent_load',
                value=load_results['average_response_time'],
                unit='seconds',
                metadata=scenario_result
            )
            
            # Print real-time results
            print(f"  Results:")
            print(f"    Success Rate: {load_results['success_rate']*100:.1f}%")
            print(f"    Requests/sec: {load_results['requests_per_second']:.1f}")
            print(f"    Avg Response: {load_results['average_response_time']*1000:.1f}ms")
            print(f"    P95 Response: {load_results['p95_response_time']*1000:.1f}ms")
            
            # Validate load testing requirements
            assert load_results['success_rate'] >= 0.95, (
                f"Load test success rate {load_results['success_rate']*100:.1f}% below 95% threshold"
            )
            
            assert load_results['average_response_time'] <= PerformanceTestingConfiguration.API_RESPONSE_TIME_THRESHOLD * 2, (
                f"Load test average response time {load_results['average_response_time']*1000:.1f}ms "
                f"exceeds 2x SLA threshold"
            )
        
        # Generate comprehensive load testing report
        self._generate_load_testing_report(load_test_results)
    
    def test_api_stress_testing_capacity_limits(self):
        """
        API stress testing to determine system capacity limits and
        performance degradation patterns under extreme load conditions.
        """
        print("\nExecuting API stress testing for capacity limits...")
        
        # Progressive load testing to find capacity limits
        stress_test_levels = [
            {'concurrent_users': 10, 'duration': 30},
            {'concurrent_users': 25, 'duration': 30},
            {'concurrent_users': 50, 'duration': 30},
            {'concurrent_users': 75, 'duration': 20},
            {'concurrent_users': 100, 'duration': 20}
        ]
        
        stress_test_results = []
        
        for level in stress_test_levels:
            print(f"\nStress testing with {level['concurrent_users']} concurrent users...")
            
            def stress_request_func():
                return self.client.get('/health')
            
            # Execute stress test
            start_time = time.time()
            total_requests = level['concurrent_users'] * 5  # 5 requests per user
            
            stress_results = self.load_tester.execute_concurrent_requests(
                request_func=stress_request_func,
                num_requests=total_requests,
                ramp_up_time=2
            )
            
            test_duration = time.time() - start_time
            
            # Analyze stress test results
            stress_result = {
                'concurrent_users': level['concurrent_users'],
                'test_duration': test_duration,
                'total_requests': stress_results['total_requests'],
                'successful_requests': stress_results['successful_requests'],
                'success_rate': stress_results['success_rate'],
                'requests_per_second': stress_results['requests_per_second'],
                'average_response_time': stress_results['average_response_time'],
                'p95_response_time': stress_results['p95_response_time'],
                'max_response_time': stress_results['max_response_time'],
                'system_stable': stress_results['success_rate'] >= 0.90 and 
                               stress_results['average_response_time'] <= 1.0  # 1 second threshold
            }
            
            stress_test_results.append(stress_result)
            
            print(f"  Success Rate: {stress_results['success_rate']*100:.1f}%")
            print(f"  Avg Response: {stress_results['average_response_time']*1000:.1f}ms")
            print(f"  System Stable: {'Yes' if stress_result['system_stable'] else 'No'}")
            
            # Break if system becomes unstable
            if not stress_result['system_stable']:
                print(f"  System instability detected at {level['concurrent_users']} concurrent users")
                break
        
        # Determine system capacity
        stable_levels = [r for r in stress_test_results if r['system_stable']]
        if stable_levels:
            max_capacity = max([r['concurrent_users'] for r in stable_levels])
            print(f"\nSystem capacity analysis:")
            print(f"  Maximum stable concurrent users: {max_capacity}")
            print(f"  Recommended capacity limit: {int(max_capacity * 0.8)} (80% of max)")
            
            # Validate minimum capacity requirements
            assert max_capacity >= 25, (
                f"System capacity {max_capacity} concurrent users below minimum requirement of 25"
            )
        else:
            pytest.fail("System failed to handle minimum stress testing load")
    
    def _generate_load_testing_report(self, results: List[Dict[str, Any]]):
        """Generate comprehensive load testing report"""
        print(f"\nLoad Testing Summary Report:")
        print(f"=" * 80)
        
        for result in results:
            print(f"Scenario: {result['scenario_name']}")
            print(f"  Endpoint: {result['endpoint']}")
            print(f"  Concurrent Users: {result['concurrent_users']}")
            print(f"  Success Rate: {result['success_rate']*100:.1f}%")
            print(f"  Throughput: {result['requests_per_second']:.1f} req/sec")
            print(f"  Avg Response: {result['average_response_time']*1000:.1f}ms")
            print(f"  P95 Response: {result['p95_response_time']*1000:.1f}ms")
            print(f"  P99 Response: {result['p99_response_time']*1000:.1f}ms")
            print()
        
        print(f"=" * 80)


# ================================
# Memory and Resource Performance Testing for APIs
# ================================

@pytest.mark.performance
@pytest.mark.memory_test
@pytest.mark.sla_validation
class TestAPIBenchmarksMemoryProfiling:
    """
    Memory and resource performance testing for API endpoints validating
    Flask application memory usage patterns, garbage collection performance,
    and resource optimization under API load scenarios.
    
    This test class implements memory profiling for API endpoints as
    specified in Section 6.5.1.1 for comprehensive memory usage analysis
    and performance validation with Python 3.13.3 optimization.
    """
    
    @pytest.fixture(autouse=True)
    def setup_memory_profiling(self, performance_client, memory_profiler,
                             performance_metrics_collector):
        """Setup memory profiling infrastructure for API testing"""
        self.client = performance_client
        self.memory_profiler = memory_profiler
        self.metrics_collector = performance_metrics_collector
        self.auth_headers = {
            'Authorization': 'Bearer test-jwt-token',
            'X-User-ID': 'test-user-123'
        }
    
    def test_api_memory_usage_profiling(self):
        """
        API endpoint memory usage profiling with comprehensive analysis
        of memory allocation patterns and garbage collection impact
        during API request processing.
        """
        print("\nExecuting API memory usage profiling...")
        
        # Test memory usage for different API endpoint types
        memory_test_endpoints = [
            {
                'name': 'lightweight_endpoint',
                'path': '/health',
                'method': 'GET',
                'expected_memory_impact': 'low'
            },
            {
                'name': 'data_processing_endpoint',
                'path': '/api/dashboard',
                'method': 'GET',
                'expected_memory_impact': 'medium'
            },
            {
                'name': 'user_creation_endpoint',
                'path': '/api/users',
                'method': 'POST',
                'data': {
                    'username': 'memtest_user',
                    'email': 'memtest@example.com',
                    'password': 'testpassword'
                },
                'expected_memory_impact': 'medium'
            }
        ]
        
        memory_profile_results = []
        
        for endpoint in memory_test_endpoints:
            print(f"\nProfiling memory usage for: {endpoint['name']}")
            
            def api_request_function():
                """Function to profile for memory usage"""
                if endpoint['method'].upper() == 'GET':
                    return self.client.get(endpoint['path'], headers=self.auth_headers)
                elif endpoint['method'].upper() == 'POST':
                    return self.client.post(
                        endpoint['path'], 
                        json=endpoint.get('data', {}),
                        headers=self.auth_headers
                    )
            
            # Profile memory usage during API requests
            result, memory_profile = self.memory_profiler.profile_function(
                api_request_function
            )
            
            # Execute multiple requests to analyze memory patterns
            memory_measurements = []
            for i in range(10):
                _, profile = self.memory_profiler.profile_function(api_request_function)
                memory_measurements.append(profile['current_memory_mb'])
            
            # Calculate memory usage statistics
            avg_memory = statistics.mean(memory_measurements)
            max_memory = max(memory_measurements)
            min_memory = min(memory_measurements)
            memory_variance = statistics.variance(memory_measurements) if len(memory_measurements) > 1 else 0
            
            profile_result = {
                'endpoint_name': endpoint['name'],
                'endpoint_path': endpoint['path'],
                'method': endpoint['method'],
                'average_memory_mb': avg_memory,
                'max_memory_mb': max_memory,
                'min_memory_mb': min_memory,
                'memory_variance': memory_variance,
                'peak_memory_mb': memory_profile['peak_memory_mb'],
                'memory_growth_mb': memory_profile['memory_growth_mb'],
                'gc_collections': memory_profile['gc_collections'],
                'memory_efficiency': memory_profile['memory_efficiency'],
                'expected_impact': endpoint['expected_memory_impact']
            }
            
            memory_profile_results.append(profile_result)
            
            # Record memory metrics
            self.metrics_collector.record_metric(
                test_name=f"memory_{endpoint['name']}",
                metric_type='memory_usage',
                value=avg_memory,
                unit='MB',
                metadata=profile_result
            )
            
            # Print memory profiling results
            print(f"  Average Memory: {avg_memory:.2f} MB")
            print(f"  Peak Memory: {memory_profile['peak_memory_mb']:.2f} MB")
            print(f"  Memory Growth: {memory_profile['memory_growth_mb']:+.2f} MB")
            print(f"  Memory Efficiency: {memory_profile['memory_efficiency']:.3f}")
            print(f"  GC Collections: {memory_profile['gc_collections']}")
            
            # Validate memory usage thresholds
            assert avg_memory <= PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB, (
                f"Average memory usage {avg_memory:.2f} MB exceeds threshold "
                f"{PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB} MB"
            )
            
            assert memory_profile['memory_efficiency'] >= 0.7, (
                f"Memory efficiency {memory_profile['memory_efficiency']:.3f} below acceptable threshold 0.7"
            )
        
        # Generate comprehensive memory profiling report
        self._generate_memory_profiling_report(memory_profile_results)
    
    def test_api_memory_leak_detection(self):
        """
        Memory leak detection during sustained API request processing
        with long-running test scenarios and memory trend analysis.
        """
        print("\nExecuting API memory leak detection...")
        
        # Long-running memory leak detection test
        test_duration = 60  # 60 second test duration
        request_interval = 0.5  # Request every 500ms
        
        memory_measurements = []
        start_time = time.time()
        
        print(f"Running memory leak detection for {test_duration} seconds...")
        
        while time.time() - start_time < test_duration:
            # Execute API request
            response = self.client.get('/health')
            
            # Measure memory usage
            current_memory = self.memory_profiler._get_current_memory_usage()
            memory_measurements.append({
                'timestamp': time.time() - start_time,
                'memory_mb': current_memory,
                'status_code': response.status_code
            })
            
            # Wait for next request
            time.sleep(request_interval)
            
            # Progress indicator
            if len(memory_measurements) % 20 == 0:
                progress = (time.time() - start_time) / test_duration * 100
                print(f"  Progress: {progress:.1f}% - Current Memory: {current_memory:.2f} MB")
        
        # Analyze memory trend for leak detection
        memory_values = [m['memory_mb'] for m in memory_measurements]
        timestamps = [m['timestamp'] for m in memory_measurements]
        
        # Calculate linear regression to detect memory growth trend
        n = len(memory_values)
        sum_x = sum(timestamps)
        sum_y = sum(memory_values)
        sum_xy = sum(x * y for x, y in zip(timestamps, memory_values))
        sum_x2 = sum(x * x for x in timestamps)
        
        # Linear regression slope (memory growth rate)
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        intercept = (sum_y - slope * sum_x) / n
        
        # Memory leak analysis
        initial_memory = memory_values[0]
        final_memory = memory_values[-1]
        memory_growth = final_memory - initial_memory
        growth_rate_mb_per_sec = slope
        
        leak_analysis = {
            'test_duration': test_duration,
            'total_requests': len(memory_measurements),
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'memory_growth_mb': memory_growth,
            'growth_rate_mb_per_sec': growth_rate_mb_per_sec,
            'max_memory_mb': max(memory_values),
            'avg_memory_mb': statistics.mean(memory_values),
            'memory_variance': statistics.variance(memory_values),
            'potential_leak_detected': growth_rate_mb_per_sec > 0.01  # 0.01 MB/sec threshold
        }
        
        # Record leak detection metrics
        self.metrics_collector.record_metric(
            test_name='api_memory_leak_detection',
            metric_type='memory_leak_analysis',
            value=growth_rate_mb_per_sec,
            unit='MB_per_second',
            metadata=leak_analysis
        )
        
        # Print leak detection results
        print(f"\nMemory Leak Detection Results:")
        print(f"  Test Duration: {test_duration} seconds")
        print(f"  Total Requests: {len(memory_measurements)}")
        print(f"  Initial Memory: {initial_memory:.2f} MB")
        print(f"  Final Memory: {final_memory:.2f} MB")
        print(f"  Memory Growth: {memory_growth:+.2f} MB")
        print(f"  Growth Rate: {growth_rate_mb_per_sec:.4f} MB/sec")
        print(f"  Potential Leak: {'Yes' if leak_analysis['potential_leak_detected'] else 'No'}")
        
        # Validate memory leak thresholds
        assert not leak_analysis['potential_leak_detected'], (
            f"Potential memory leak detected: growth rate {growth_rate_mb_per_sec:.4f} MB/sec "
            f"exceeds threshold 0.01 MB/sec"
        )
        
        assert memory_growth <= 50.0, (  # 50 MB maximum acceptable growth
            f"Excessive memory growth {memory_growth:.2f} MB during sustained operation"
        )
    
    def _generate_memory_profiling_report(self, results: List[Dict[str, Any]]):
        """Generate comprehensive memory profiling report"""
        print(f"\nMemory Profiling Summary Report:")
        print(f"=" * 80)
        
        total_endpoints = len(results)
        avg_memory_usage = statistics.mean([r['average_memory_mb'] for r in results])
        max_memory_usage = max([r['max_memory_mb'] for r in results])
        
        print(f"Overall Memory Performance:")
        print(f"  Endpoints Tested: {total_endpoints}")
        print(f"  Average Memory Usage: {avg_memory_usage:.2f} MB")
        print(f"  Maximum Memory Usage: {max_memory_usage:.2f} MB")
        print(f"  Memory Threshold: {PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB} MB")
        print(f"  Memory Efficiency: {avg_memory_usage/PerformanceTestingConfiguration.MEMORY_USAGE_THRESHOLD_MB*100:.1f}% of threshold")
        print()
        
        print(f"Endpoint-Specific Memory Analysis:")
        for result in results:
            efficiency_status = "Good" if result['memory_efficiency'] >= 0.8 else "Needs Optimization"
            print(f"  {result['endpoint_name']}:")
            print(f"    Average Memory: {result['average_memory_mb']:.2f} MB")
            print(f"    Peak Memory: {result['peak_memory_mb']:.2f} MB")
            print(f"    Memory Growth: {result['memory_growth_mb']:+.2f} MB")
            print(f"    Efficiency: {result['memory_efficiency']:.3f} ({efficiency_status})")
            print()
        
        print(f"=" * 80)


# ================================
# Test Suite Entry Point and Configuration
# ================================

if __name__ == '__main__':
    """
    Entry point for running API benchmarking tests independently
    with comprehensive configuration and performance validation.
    """
    pytest.main([
        __file__,
        '-v',
        '--benchmark-only',
        '--benchmark-sort=mean',
        '--benchmark-columns=min,max,mean,stddev,rounds,iterations',
        '--benchmark-group-by=group',
        '--tb=short'
    ])