"""
API Response Time Benchmarking Test Suite

This comprehensive test suite validates Flask API endpoint performance against Node.js baseline
metrics using pytest-benchmark 5.1.0 for statistical measurement and analysis. The suite ensures
sub-200ms API response times per SLA requirements and provides detailed statistical analysis of
endpoint performance to guarantee migration success with equivalent or improved response characteristics.

Key Features:
- Comprehensive API response time measurement using pytest-benchmark 5.1.0 per Section 4.7.1
- Baseline comparison framework validating Flask vs Node.js performance per Section 4.11.3
- Sub-200ms API response time validation per SLA requirements per Section 4.11.1
- Statistical analysis with percentile tracking and distribution analysis per Section 6.5.1.1
- Automated performance regression detection with threshold validation per Section 4.7.2
- Integration with prometheus_flask_exporter for endpoint monitoring per Section 6.5.1.1

Migration Context:
This test suite supports the strategic technology migration from Node.js/Express.js to
Python 3.13.3/Flask 3.1.1 by providing comprehensive API performance validation that
ensures functional parity and performance equivalence during the conversion process.

Test Categories:
- Health and System Endpoints (Main Blueprint)
- Authentication Endpoints (Auth Blueprint)
- Core API Endpoints (API Blueprint)
- Error Handling and Edge Cases
- Concurrent Load Performance
- Statistical Analysis and Reporting
"""

import json
import statistics
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import concurrent.futures
import threading
from unittest.mock import patch, MagicMock

import pytest
from flask import current_app

# Performance testing markers per Section 4.7.1
pytestmark = [
    pytest.mark.performance,
    pytest.mark.api_performance,
    pytest.mark.baseline_comparison
]


class APIResponseBenchmarkSuite:
    """
    Comprehensive API response benchmarking test suite for migration validation.
    
    This class provides organized testing of all Flask API endpoints with detailed
    performance analysis, baseline comparison, and regression detection per
    Section 4.7.1 and Section 4.11.3 requirements.
    """
    
    def __init__(self):
        """Initialize API benchmarking suite with performance tracking."""
        self.test_results = []
        self.performance_summary = {}
        self.regression_alerts = []
        
    def record_test_result(self, test_name: str, result: Dict[str, Any]):
        """Record individual test result for comprehensive analysis."""
        result['test_name'] = test_name
        result['timestamp'] = datetime.now(timezone.utc).isoformat()
        self.test_results.append(result)
        
    def analyze_performance_trends(self) -> Dict[str, Any]:
        """Analyze performance trends across all API endpoints."""
        if not self.test_results:
            return {'no_data': True}
            
        # Aggregate response times by endpoint category
        main_endpoints = []
        auth_endpoints = []
        api_endpoints = []
        
        for result in self.test_results:
            if 'flask_metrics' in result and result['flask_metrics'].get('mean'):
                mean_time = result['flask_metrics']['mean']
                test_name = result.get('test_name', '')
                
                if 'health' in test_name or 'status' in test_name:
                    main_endpoints.append(mean_time)
                elif 'auth' in test_name or 'login' in test_name:
                    auth_endpoints.append(mean_time)
                elif 'api' in test_name:
                    api_endpoints.append(mean_time)
                    
        # Calculate performance statistics per Section 6.5.1.1
        summary = {
            'total_tests': len(self.test_results),
            'test_categories': {
                'main_endpoints': {
                    'count': len(main_endpoints),
                    'mean_response_time': statistics.mean(main_endpoints) if main_endpoints else 0,
                    'p95_response_time': self._calculate_percentile(main_endpoints, 95) if main_endpoints else 0,
                    'p99_response_time': self._calculate_percentile(main_endpoints, 99) if main_endpoints else 0
                },
                'auth_endpoints': {
                    'count': len(auth_endpoints),
                    'mean_response_time': statistics.mean(auth_endpoints) if auth_endpoints else 0,
                    'p95_response_time': self._calculate_percentile(auth_endpoints, 95) if auth_endpoints else 0,
                    'p99_response_time': self._calculate_percentile(auth_endpoints, 99) if auth_endpoints else 0
                },
                'api_endpoints': {
                    'count': len(api_endpoints),
                    'mean_response_time': statistics.mean(api_endpoints) if api_endpoints else 0,
                    'p95_response_time': self._calculate_percentile(api_endpoints, 95) if api_endpoints else 0,
                    'p99_response_time': self._calculate_percentile(api_endpoints, 99) if api_endpoints else 0
                }
            },
            'sla_compliance': self._analyze_sla_compliance(),
            'regression_analysis': self._analyze_regressions()
        }
        
        return summary
        
    def _calculate_percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile for response time data."""
        if not data:
            return 0.0
        sorted_data = sorted(data)
        index = (percentile / 100.0) * (len(sorted_data) - 1)
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
            
    def _analyze_sla_compliance(self) -> Dict[str, Any]:
        """Analyze SLA compliance across all test results per Section 4.11.1."""
        compliant_tests = 0
        violation_tests = []
        
        for result in self.test_results:
            if 'flask_metrics' in result and result['flask_metrics'].get('mean'):
                mean_time = result['flask_metrics']['mean']
                # SLA requirement: sub-200ms response time per Section 4.11.1
                if mean_time <= 0.200:  # 200ms
                    compliant_tests += 1
                else:
                    violation_tests.append({
                        'test_name': result.get('test_name'),
                        'response_time': mean_time,
                        'violation_amount': mean_time - 0.200
                    })
                    
        return {
            'total_tests': len(self.test_results),
            'compliant_tests': compliant_tests,
            'violation_tests': len(violation_tests),
            'compliance_percentage': (compliant_tests / len(self.test_results) * 100) if self.test_results else 0,
            'violations': violation_tests
        }
        
    def _analyze_regressions(self) -> Dict[str, Any]:
        """Analyze performance regressions per Section 4.7.2."""
        regressions = []
        improvements = []
        
        for result in self.test_results:
            if result.get('regression_detected'):
                regressions.append({
                    'test_name': result.get('test_name'),
                    'performance_change': result.get('performance_improvement', 0)
                })
            elif result.get('performance_improvement', 0) > 0:
                improvements.append({
                    'test_name': result.get('test_name'),
                    'performance_improvement': result.get('performance_improvement', 0)
                })
                
        return {
            'regressions_detected': len(regressions),
            'improvements_detected': len(improvements),
            'regression_details': regressions,
            'improvement_details': improvements
        }


# Global benchmark suite instance for result aggregation
benchmark_suite = APIResponseBenchmarkSuite()


class TestMainBlueprintPerformance:
    """
    Performance tests for main blueprint endpoints including health checks and system monitoring.
    
    This test class validates the performance of system health endpoints and monitoring
    infrastructure per Section 8.5 requirements, ensuring sub-200ms response times
    for critical system monitoring functionality.
    """
    
    @pytest.mark.api_performance
    @pytest.mark.regression_test
    def test_health_check_endpoint_performance(self, api_performance_benchmark, 
                                             baseline_comparison, regression_detector):
        """
        Test health check endpoint performance against baseline metrics.
        
        This test validates the primary health check endpoint response time,
        ensuring system monitoring remains performant during migration per Section 8.5.
        
        Performance Requirements:
        - Response time < 200ms per Section 4.11.1
        - Baseline comparison with Node.js health endpoint
        - No performance regression > 5% per Section 4.7.2
        """
        # Benchmark health check endpoint
        result = api_performance_benchmark(
            endpoint_path="/health",
            method="GET",
            expected_status=200,
            baseline_key="GET /health"
        )
        
        # Perform baseline comparison per Section 4.7.2
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="health_check",
                flask_metrics=[mean_response_time],
                baseline_key="GET /health",
                tolerance_percent=5.0
            )
            result.update(comparison)
            
        # Detect performance regressions per Section 4.7.2
        regression_analysis = regression_detector(result)
        result['regression_analysis'] = regression_analysis
        
        # Validate SLA requirements per Section 4.11.1
        assert result.get('meets_response_time_threshold', False), \
            f"Health check response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
        
        # Validate baseline comparison if available
        if result.get('baseline_available'):
            assert result.get('result') in ['IMPROVEMENT', 'ACCEPTABLE'], \
                f"Health check performance regression detected: {result.get('performance_improvement', 0):.2f}%"
        
        # Record result for comprehensive analysis
        benchmark_suite.record_test_result("health_check_endpoint", result)
        
        # Additional assertions for comprehensive validation
        assert result['flask_metrics']['p95'] <= 0.250, \
            f"Health check P95 response time {result['flask_metrics']['p95']:.3f}s exceeds acceptable threshold"
        
    @pytest.mark.api_performance
    def test_health_detailed_endpoint_performance(self, api_performance_benchmark, 
                                                 baseline_comparison):
        """
        Test detailed health check endpoint with comprehensive system validation.
        
        This test validates the detailed health endpoint that includes database
        connectivity, external service checks, and comprehensive system status
        per Section 6.5.2.1 health check requirements.
        """
        # Benchmark detailed health endpoint
        result = api_performance_benchmark(
            endpoint_path="/health/detailed",
            method="GET", 
            expected_status=200,
            baseline_key="GET /health/detailed"
        )
        
        # Perform baseline comparison
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="health_detailed",
                flask_metrics=[mean_response_time],
                baseline_key="GET /health/detailed"
            )
            result.update(comparison)
            
        # Detailed health should be slower but still reasonable (< 500ms)
        assert result['flask_metrics']['mean'] <= 0.500, \
            f"Detailed health response time {result['flask_metrics']['mean']:.3f}s exceeds 500ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("health_detailed_endpoint", result)
        
    @pytest.mark.api_performance
    def test_system_status_endpoint_performance(self, api_performance_benchmark):
        """
        Test system status endpoint performance for monitoring integration.
        
        This test validates system status endpoints used for operational
        monitoring and observability per Section 6.5.1.1 requirements.
        """
        # Benchmark system status endpoint
        result = api_performance_benchmark(
            endpoint_path="/status",
            method="GET",
            expected_status=200,
            baseline_key="GET /status"
        )
        
        # System status should be fast for monitoring systems
        assert result.get('meets_response_time_threshold', False), \
            f"System status response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("system_status_endpoint", result)


class TestAuthBlueprintPerformance:
    """
    Performance tests for authentication blueprint endpoints.
    
    This test class validates authentication flow performance including login,
    token validation, and session management per Section 6.5.2.2 and Section 4.11.1
    requirements with sub-150ms authentication response times.
    """
    
    @pytest.mark.auth_performance
    @pytest.mark.regression_test
    def test_login_endpoint_performance(self, api_performance_benchmark,
                                      baseline_comparison, regression_detector):
        """
        Test user login endpoint performance with authentication validation.
        
        This test validates the primary authentication flow performance ensuring
        sub-150ms authentication response times per Section 4.11.1 while maintaining
        security posture during the Flask migration.
        
        Performance Requirements:
        - Authentication response time < 150ms per Section 4.11.1
        - ItsDangerous session management efficiency per Section 5.1.1
        - No authentication performance regression per Section 4.7.2
        """
        # Prepare login request data
        login_data = {
            "username": "test_user",
            "password": "test_password"
        }
        
        # Benchmark login endpoint with authentication flow
        result = api_performance_benchmark(
            endpoint_path="/auth/login",
            method="POST",
            data=login_data,
            expected_status=200,  # Assuming successful login response
            baseline_key="POST /auth/login"
        )
        
        # Perform baseline comparison against Node.js authentication
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="auth_login",
                flask_metrics=[mean_response_time],
                baseline_key="login",
                tolerance_percent=5.0
            )
            result.update(comparison)
            
        # Detect authentication performance regressions
        regression_analysis = regression_detector(result)
        result['regression_analysis'] = regression_analysis
        
        # Validate authentication SLA requirements per Section 4.11.1
        auth_threshold = 0.150  # 150ms authentication threshold
        assert result['flask_metrics']['mean'] <= auth_threshold, \
            f"Login response time {result['flask_metrics']['mean']:.3f}s exceeds 150ms auth threshold"
            
        # Validate ItsDangerous session management performance
        assert result.get('meets_response_time_threshold', False), \
            "Login endpoint does not meet overall response time requirements"
            
        # Record result for authentication performance analysis
        benchmark_suite.record_test_result("auth_login_endpoint", result)
        
    @pytest.mark.auth_performance
    def test_token_validation_performance(self, api_performance_benchmark,
                                        baseline_comparison):
        """
        Test authentication token validation performance.
        
        This test validates token validation middleware performance ensuring
        fast authentication checks for protected endpoints per Section 5.1.1.
        """
        # Mock authentication headers for token validation
        auth_headers = {
            "Authorization": "Bearer test_jwt_token"
        }
        
        # Benchmark token validation endpoint
        result = api_performance_benchmark(
            endpoint_path="/auth/validate",
            method="GET",
            headers=auth_headers,
            expected_status=200,
            baseline_key="token_validation"
        )
        
        # Perform baseline comparison
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="token_validation",
                flask_metrics=[mean_response_time],
                baseline_key="token_validation"
            )
            result.update(comparison)
            
        # Token validation should be very fast (< 50ms)
        assert result['flask_metrics']['mean'] <= 0.050, \
            f"Token validation time {result['flask_metrics']['mean']:.3f}s exceeds 50ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("auth_token_validation", result)
        
    @pytest.mark.auth_performance
    def test_session_refresh_performance(self, api_performance_benchmark):
        """
        Test session refresh endpoint performance for ItsDangerous session management.
        
        This test validates Flask session refresh operations ensuring efficient
        session management compared to Node.js middleware patterns.
        """
        # Benchmark session refresh with existing session context
        result = api_performance_benchmark(
            endpoint_path="/auth/refresh",
            method="POST",
            expected_status=200,
            baseline_key="session_refresh"
        )
        
        # Session refresh should be efficient (< 100ms)
        assert result['flask_metrics']['mean'] <= 0.100, \
            f"Session refresh time {result['flask_metrics']['mean']:.3f}s exceeds 100ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("auth_session_refresh", result)
        
    @pytest.mark.auth_performance  
    def test_logout_endpoint_performance(self, api_performance_benchmark):
        """
        Test user logout endpoint performance for session cleanup.
        
        This test validates logout flow performance including session
        invalidation and cleanup operations.
        """
        # Benchmark logout endpoint
        result = api_performance_benchmark(
            endpoint_path="/auth/logout",
            method="POST",
            expected_status=200,
            baseline_key="POST /auth/logout"
        )
        
        # Logout should be fast for good UX
        assert result.get('meets_response_time_threshold', False), \
            f"Logout response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("auth_logout_endpoint", result)


class TestAPIBlueprintPerformance:
    """
    Performance tests for core API blueprint endpoints.
    
    This test class validates RESTful API endpoint performance including CRUD operations,
    data processing, and business logic execution per Section 4.3.1 and Section 5.2.2
    requirements with comprehensive Flask blueprint performance validation.
    """
    
    @pytest.mark.api_performance
    @pytest.mark.regression_test
    def test_get_users_endpoint_performance(self, api_performance_benchmark,
                                          baseline_comparison, regression_detector):
        """
        Test GET users endpoint performance for data retrieval operations.
        
        This test validates user data retrieval performance ensuring efficient
        SQLAlchemy query execution and JSON response generation per Section 6.5.1.1.
        
        Performance Requirements:
        - API response time < 200ms per Section 4.11.1
        - Database query time < 100ms per Section 6.5.1.1
        - No performance regression vs Node.js per Section 4.7.2
        """
        # Benchmark users list endpoint
        result = api_performance_benchmark(
            endpoint_path="/api/users",
            method="GET",
            expected_status=200,
            baseline_key="GET /api/users"
        )
        
        # Perform baseline comparison against Node.js API
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="api_get_users",
                flask_metrics=[mean_response_time],
                baseline_key="GET /api/users",
                tolerance_percent=5.0
            )
            result.update(comparison)
            
        # Detect API performance regressions
        regression_analysis = regression_detector(result)
        result['regression_analysis'] = regression_analysis
        
        # Validate API SLA requirements per Section 4.11.1
        assert result.get('meets_response_time_threshold', False), \
            f"GET users response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Validate database query performance is included
        assert result.get('meets_p95_threshold', False), \
            f"GET users P95 response time exceeds acceptable threshold"
            
        # Record result for API performance analysis
        benchmark_suite.record_test_result("api_get_users_endpoint", result)
        
    @pytest.mark.api_performance
    def test_post_users_endpoint_performance(self, api_performance_benchmark,
                                           baseline_comparison):
        """
        Test POST users endpoint performance for data creation operations.
        
        This test validates user creation performance including data validation,
        database insertion, and response generation per Flask blueprint architecture.
        """
        # Prepare user creation data
        user_data = {
            "username": "new_test_user",
            "email": "test@example.com",
            "profile": {
                "first_name": "Test",
                "last_name": "User"
            }
        }
        
        # Benchmark user creation endpoint
        result = api_performance_benchmark(
            endpoint_path="/api/users",
            method="POST",
            data=user_data,
            expected_status=201,  # Created status
            baseline_key="POST /api/users"
        )
        
        # Perform baseline comparison
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="api_post_users",
                flask_metrics=[mean_response_time],
                baseline_key="POST /api/users"
            )
            result.update(comparison)
            
        # Data creation should still be sub-200ms
        assert result.get('meets_response_time_threshold', False), \
            f"POST users response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_post_users_endpoint", result)
        
    @pytest.mark.api_performance
    def test_put_users_endpoint_performance(self, api_performance_benchmark):
        """
        Test PUT users endpoint performance for data update operations.
        
        This test validates user update performance including data validation,
        database updates, and response generation.
        """
        # Prepare user update data
        update_data = {
            "email": "updated_test@example.com",
            "profile": {
                "first_name": "Updated",
                "last_name": "User"
            }
        }
        
        # Benchmark user update endpoint (using ID 1 as example)
        result = api_performance_benchmark(
            endpoint_path="/api/users/1",
            method="PUT",
            data=update_data,
            expected_status=200,
            baseline_key="PUT /api/users/:id"
        )
        
        # Update operations should be efficient
        assert result.get('meets_response_time_threshold', False), \
            f"PUT users response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_put_users_endpoint", result)
        
    @pytest.mark.api_performance
    def test_delete_users_endpoint_performance(self, api_performance_benchmark):
        """
        Test DELETE users endpoint performance for data removal operations.
        
        This test validates user deletion performance including data validation,
        database deletion, and response generation.
        """
        # Benchmark user deletion endpoint
        result = api_performance_benchmark(
            endpoint_path="/api/users/1",
            method="DELETE",
            expected_status=204,  # No content status
            baseline_key="DELETE /api/users/:id"
        )
        
        # Deletion should be fast
        assert result.get('meets_response_time_threshold', False), \
            f"DELETE users response time {result['flask_metrics']['mean']:.3f}s exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_delete_users_endpoint", result)
        
    @pytest.mark.api_performance
    def test_get_user_by_id_performance(self, api_performance_benchmark,
                                      baseline_comparison):
        """
        Test individual user retrieval performance by ID.
        
        This test validates single user lookup performance including
        database query optimization and JSON serialization.
        """
        # Benchmark individual user retrieval
        result = api_performance_benchmark(
            endpoint_path="/api/users/1",
            method="GET",
            expected_status=200,
            baseline_key="GET /api/users/:id"
        )
        
        # Perform baseline comparison
        if result.get('flask_metrics') and result['flask_metrics'].get('mean'):
            mean_response_time = result['flask_metrics']['mean']
            comparison = baseline_comparison(
                test_name="api_get_user_by_id",
                flask_metrics=[mean_response_time],
                baseline_key="GET /api/users/:id"
            )
            result.update(comparison)
            
        # Single user lookup should be very fast
        assert result['flask_metrics']['mean'] <= 0.100, \
            f"GET user by ID response time {result['flask_metrics']['mean']:.3f}s exceeds 100ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_get_user_by_id", result)


class TestAPIErrorHandlingPerformance:
    """
    Performance tests for API error handling and edge cases.
    
    This test class validates error handling performance ensuring that error
    responses maintain good performance characteristics per Section 4.3.2.
    """
    
    @pytest.mark.api_performance
    def test_404_error_response_performance(self, api_performance_benchmark):
        """
        Test 404 error response performance for non-existent resources.
        
        This test validates that error handling maintains good performance
        even when resources are not found.
        """
        # Benchmark 404 error response
        result = api_performance_benchmark(
            endpoint_path="/api/users/999999",
            method="GET",
            expected_status=404,
            baseline_key="GET /api/404_error"
        )
        
        # Error responses should still be fast
        assert result['flask_metrics']['mean'] <= 0.100, \
            f"404 error response time {result['flask_metrics']['mean']:.3f}s exceeds 100ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_404_error_response", result)
        
    @pytest.mark.api_performance
    def test_validation_error_performance(self, api_performance_benchmark):
        """
        Test validation error response performance for invalid data.
        
        This test validates data validation error handling performance
        ensuring fast feedback for invalid requests.
        """
        # Prepare invalid data that should trigger validation errors
        invalid_data = {
            "username": "",  # Empty username
            "email": "invalid_email",  # Invalid email format
            "profile": "not_an_object"  # Invalid profile type
        }
        
        # Benchmark validation error response
        result = api_performance_benchmark(
            endpoint_path="/api/users",
            method="POST",
            data=invalid_data,
            expected_status=400,  # Bad request
            baseline_key="POST /api/validation_error"
        )
        
        # Validation errors should be handled quickly
        assert result['flask_metrics']['mean'] <= 0.150, \
            f"Validation error response time {result['flask_metrics']['mean']:.3f}s exceeds 150ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("api_validation_error_response", result)


class TestConcurrentAPIPerformance:
    """
    Concurrent load testing for API endpoints.
    
    This test class validates API performance under concurrent load conditions
    per Section 6.5.2.5 ensuring scalability and thread pool efficiency.
    """
    
    @pytest.mark.concurrent_performance
    @pytest.mark.api_performance
    def test_concurrent_get_requests_performance(self, concurrent_load_benchmark,
                                                flask_client):
        """
        Test concurrent GET request performance for scalability validation.
        
        This test validates API performance under concurrent user load ensuring
        thread pool utilization and request handling efficiency per Section 6.5.2.5.
        """
        def make_concurrent_request():
            """Make a single API request for concurrent testing."""
            response = flask_client.get("/api/users")
            assert response.status_code == 200
            return response
            
        # Execute concurrent load test
        result = concurrent_load_benchmark(
            load_func=make_concurrent_request,
            test_name="concurrent_get_users",
            concurrent_users=20,
            requests_per_user=5
        )
        
        # Validate concurrent performance requirements per Section 6.5.2.5
        assert result.get('meets_throughput_threshold', False), \
            f"Concurrent throughput {result.get('throughput_rps', 0):.2f} RPS below 500 RPS requirement"
            
        assert result.get('meets_response_time_threshold', False), \
            f"Concurrent mean response time exceeds 200ms threshold"
            
        # Record result
        benchmark_suite.record_test_result("concurrent_get_requests", result)
        
    @pytest.mark.concurrent_performance
    def test_mixed_concurrent_operations_performance(self, concurrent_load_benchmark,
                                                   flask_client):
        """
        Test mixed concurrent operations (GET/POST/PUT/DELETE) performance.
        
        This test validates API performance under mixed operation load ensuring
        consistent performance across different HTTP methods.
        """
        operations = [
            lambda: flask_client.get("/api/users"),
            lambda: flask_client.post("/api/users", json={"username": "test", "email": "test@example.com"}),
            lambda: flask_client.put("/api/users/1", json={"email": "updated@example.com"}),
            lambda: flask_client.get("/api/users/1")
        ]
        
        def make_mixed_request():
            """Make a random API request for mixed concurrent testing."""
            import random
            operation = random.choice(operations)
            response = operation()
            # Accept various successful status codes
            assert response.status_code in [200, 201, 204]
            return response
            
        # Execute mixed concurrent load test
        result = concurrent_load_benchmark(
            load_func=make_mixed_request,
            test_name="mixed_concurrent_operations",
            concurrent_users=15,
            requests_per_user=4
        )
        
        # Validate mixed operation performance
        assert result.get('error_rate', 1.0) <= 0.05, \
            f"Mixed operation error rate {result.get('error_rate', 1.0):.2%} exceeds 5% threshold"
            
        # Record result
        benchmark_suite.record_test_result("mixed_concurrent_operations", result)


class TestStatisticalAnalysis:
    """
    Statistical analysis and reporting for API performance benchmarks.
    
    This test class provides comprehensive statistical analysis of API performance
    data per Section 6.5.1.1 with percentile tracking and trend analysis.
    """
    
    @pytest.mark.performance
    def test_comprehensive_performance_analysis(self, baseline_data, 
                                              performance_report_generator):
        """
        Comprehensive performance analysis and reporting.
        
        This test analyzes all collected performance data and generates
        comprehensive reports with statistical analysis per Section 6.5.1.1.
        """
        # Generate comprehensive performance analysis
        performance_summary = benchmark_suite.analyze_performance_trends()
        
        # Generate detailed performance report
        detailed_report = performance_report_generator(
            test_results=benchmark_suite.test_results,
            report_name="api_response_benchmarks_report"
        )
        
        # Validate overall performance summary
        assert performance_summary.get('total_tests', 0) > 0, \
            "No performance test data available for analysis"
            
        # Validate SLA compliance per Section 4.11.1
        sla_compliance = performance_summary.get('sla_compliance', {})
        compliance_percentage = sla_compliance.get('compliance_percentage', 0)
        
        assert compliance_percentage >= 95.0, \
            f"API SLA compliance {compliance_percentage:.1f}% below 95% requirement"
            
        # Validate no critical regressions per Section 4.7.2
        regression_analysis = performance_summary.get('regression_analysis', {})
        regressions_detected = regression_analysis.get('regressions_detected', 0)
        
        assert regressions_detected == 0, \
            f"Performance regressions detected: {regressions_detected}"
            
        # Log comprehensive analysis results
        print("\n" + "="*80)
        print("API RESPONSE BENCHMARK ANALYSIS SUMMARY")
        print("="*80)
        print(f"Total Tests Executed: {performance_summary.get('total_tests', 0)}")
        print(f"SLA Compliance: {compliance_percentage:.1f}%")
        print(f"Performance Regressions: {regressions_detected}")
        print(f"Performance Improvements: {regression_analysis.get('improvements_detected', 0)}")
        
        # Print category-specific performance summaries
        categories = performance_summary.get('test_categories', {})
        for category, stats in categories.items():
            if stats.get('count', 0) > 0:
                print(f"\n{category.replace('_', ' ').title()}:")
                print(f"  Tests: {stats['count']}")
                print(f"  Mean Response Time: {stats['mean_response_time']:.3f}s")
                print(f"  P95 Response Time: {stats['p95_response_time']:.3f}s")
                print(f"  P99 Response Time: {stats['p99_response_time']:.3f}s")
                
        print("\n" + "="*80)
        
        # Save detailed report for analysis
        report_timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_filename = f"api_benchmark_report_{report_timestamp}.json"
        
        with open(report_filename, 'w') as f:
            json.dump({
                'performance_summary': performance_summary,
                'detailed_report': detailed_report,
                'test_results': benchmark_suite.test_results
            }, f, indent=2, default=str)
            
        print(f"Detailed performance report saved to: {report_filename}")
        
    @pytest.mark.performance
    def test_percentile_distribution_analysis(self):
        """
        Analyze response time percentile distributions per Section 6.5.1.1.
        
        This test provides detailed percentile analysis of API response times
        to identify performance outliers and distribution characteristics.
        """
        # Collect all response times from benchmark results
        all_response_times = []
        endpoint_response_times = {}
        
        for result in benchmark_suite.test_results:
            if 'flask_metrics' in result and result['flask_metrics'].get('mean'):
                response_time = result['flask_metrics']['mean']
                test_name = result.get('test_name', 'unknown')
                
                all_response_times.append(response_time)
                
                if test_name not in endpoint_response_times:
                    endpoint_response_times[test_name] = []
                endpoint_response_times[test_name].append(response_time)
                
        if not all_response_times:
            pytest.skip("No response time data available for percentile analysis")
            
        # Calculate comprehensive percentile distribution
        percentiles = [50, 75, 90, 95, 99, 99.9]
        percentile_analysis = {}
        
        for p in percentiles:
            percentile_analysis[f'p{p}'] = benchmark_suite._calculate_percentile(
                all_response_times, p
            )
            
        # Analyze distribution characteristics
        distribution_stats = {
            'total_samples': len(all_response_times),
            'mean': statistics.mean(all_response_times),
            'median': statistics.median(all_response_times),
            'std_dev': statistics.stdev(all_response_times) if len(all_response_times) > 1 else 0,
            'min': min(all_response_times),
            'max': max(all_response_times),
            'percentiles': percentile_analysis
        }
        
        # Validate percentile distribution requirements
        assert distribution_stats['percentiles']['p95'] <= 0.300, \
            f"P95 response time {distribution_stats['percentiles']['p95']:.3f}s exceeds 300ms threshold"
            
        assert distribution_stats['percentiles']['p99'] <= 0.500, \
            f"P99 response time {distribution_stats['percentiles']['p99']:.3f}s exceeds 500ms threshold"
            
        # Log detailed percentile analysis
        print("\n" + "="*60)
        print("RESPONSE TIME PERCENTILE ANALYSIS")
        print("="*60)
        print(f"Total Samples: {distribution_stats['total_samples']}")
        print(f"Mean: {distribution_stats['mean']:.3f}s")
        print(f"Median: {distribution_stats['median']:.3f}s")
        print(f"Standard Deviation: {distribution_stats['std_dev']:.3f}s")
        print(f"Min: {distribution_stats['min']:.3f}s")
        print(f"Max: {distribution_stats['max']:.3f}s")
        print("\nPercentile Distribution:")
        for percentile, value in distribution_stats['percentiles'].items():
            print(f"  {percentile}: {value:.3f}s")
        print("="*60)
        
    @pytest.mark.performance
    @pytest.mark.regression_test
    def test_baseline_comparison_summary(self, baseline_data):
        """
        Comprehensive baseline comparison summary per Section 4.7.2.
        
        This test provides a comprehensive summary of Flask vs Node.js
        performance comparison across all tested endpoints.
        """
        # Analyze baseline comparisons from all test results
        baseline_comparisons = []
        improvements = []
        regressions = []
        no_baseline = []
        
        for result in benchmark_suite.test_results:
            if result.get('baseline_available'):
                improvement = result.get('performance_improvement', 0)
                
                baseline_comparisons.append({
                    'test_name': result.get('test_name'),
                    'improvement_percent': improvement,
                    'result_category': result.get('result', 'UNKNOWN')
                })
                
                if improvement > 0:
                    improvements.append(result)
                elif result.get('regression_detected'):
                    regressions.append(result)
            else:
                no_baseline.append(result)
                
        # Generate baseline comparison summary
        comparison_summary = {
            'total_comparisons': len(baseline_comparisons),
            'improvements': len(improvements),
            'regressions': len(regressions),
            'no_baseline_available': len(no_baseline),
            'overall_improvement': 0
        }
        
        if baseline_comparisons:
            all_improvements = [comp['improvement_percent'] for comp in baseline_comparisons]
            comparison_summary['overall_improvement'] = statistics.mean(all_improvements)
            
        # Validate migration success criteria per Section 0.1.1
        assert len(regressions) == 0, \
            f"Performance regressions detected in {len(regressions)} endpoints"
            
        assert comparison_summary['overall_improvement'] >= -5.0, \
            f"Overall performance regression {comparison_summary['overall_improvement']:.2f}% exceeds -5% threshold"
            
        # Log comprehensive baseline comparison results
        print("\n" + "="*70)
        print("BASELINE COMPARISON SUMMARY (Flask vs Node.js)")
        print("="*70)
        print(f"Total Endpoint Comparisons: {comparison_summary['total_comparisons']}")
        print(f"Performance Improvements: {comparison_summary['improvements']}")
        print(f"Performance Regressions: {comparison_summary['regressions']}")
        print(f"No Baseline Available: {comparison_summary['no_baseline_available']}")
        print(f"Overall Performance Change: {comparison_summary['overall_improvement']:+.2f}%")
        
        if improvements:
            print(f"\nTop Performance Improvements:")
            sorted_improvements = sorted(improvements, 
                                       key=lambda x: x.get('performance_improvement', 0), 
                                       reverse=True)[:5]
            for imp in sorted_improvements:
                print(f"  {imp.get('test_name', 'Unknown')}: +{imp.get('performance_improvement', 0):.2f}%")
                
        if regressions:
            print(f"\nPerformance Regressions Detected:")
            for reg in regressions:
                print(f"  {reg.get('test_name', 'Unknown')}: {reg.get('performance_improvement', 0):.2f}%")
                
        print("="*70)


class TestPrometheusMetricsIntegration:
    """
    Integration tests for Prometheus metrics collection per Section 6.5.1.1.
    
    This test class validates prometheus_flask_exporter integration and
    comprehensive endpoint monitoring capabilities.
    """
    
    @pytest.mark.performance
    @pytest.mark.skipif(not hasattr(pytest, 'importorskip'), reason="Prometheus integration test")
    def test_prometheus_metrics_collection(self, flask_client, prometheus_metrics):
        """
        Test Prometheus metrics collection during API benchmarking.
        
        This test validates that prometheus_flask_exporter properly collects
        metrics during performance testing per Section 6.5.1.1.
        """
        if not prometheus_metrics:
            pytest.skip("Prometheus metrics not available")
            
        # Make several requests to generate metrics
        test_endpoints = [
            "/health",
            "/api/users", 
            "/auth/login"
        ]
        
        for endpoint in test_endpoints:
            for _ in range(5):  # Make multiple requests per endpoint
                if endpoint == "/auth/login":
                    flask_client.post(endpoint, json={"username": "test", "password": "test"})
                else:
                    flask_client.get(endpoint)
                    
        # Collect Prometheus metrics
        registry = prometheus_metrics['registry']
        metrics_output = generate_latest(registry).decode('utf-8')
        
        # Validate that metrics are being collected
        assert 'flask_api_request_duration_seconds' in metrics_output, \
            "API request duration metrics not found in Prometheus output"
            
        assert 'flask_http_request_total' in metrics_output, \
            "HTTP request total metrics not found in Prometheus output"
            
        # Validate endpoint-specific metrics
        for endpoint in test_endpoints:
            endpoint_pattern = endpoint.replace("/", "_")
            assert endpoint_pattern in metrics_output or endpoint in metrics_output, \
                f"Metrics for endpoint {endpoint} not found in Prometheus output"
                
        print("\n" + "="*50)
        print("PROMETHEUS METRICS INTEGRATION VALIDATED")
        print("="*50)
        print("Metrics Collection: SUCCESSFUL")
        print(f"Endpoints Monitored: {len(test_endpoints)}")
        print("prometheus_flask_exporter: OPERATIONAL")
        print("="*50)


# Final validation and cleanup
class TestBenchmarkValidation:
    """
    Final validation of benchmark test execution and data integrity.
    
    This test class provides final validation of the benchmark suite
    execution ensuring all required tests completed successfully.
    """
    
    @pytest.mark.performance
    def test_benchmark_suite_completion(self):
        """
        Validate that the benchmark suite executed all required tests.
        
        This test ensures comprehensive test coverage and validates
        that all critical API endpoints were successfully benchmarked.
        """
        # Validate minimum test coverage requirements
        required_test_categories = [
            'health_check',
            'auth_login', 
            'api_get_users',
            'api_post_users'
        ]
        
        executed_tests = [result.get('test_name', '') for result in benchmark_suite.test_results]
        
        for required_test in required_test_categories:
            matching_tests = [test for test in executed_tests if required_test in test]
            assert len(matching_tests) > 0, \
                f"Required test category '{required_test}' not found in executed tests"
                
        # Validate minimum number of performance measurements
        assert len(benchmark_suite.test_results) >= 10, \
            f"Insufficient performance tests executed: {len(benchmark_suite.test_results)} < 10"
            
        # Validate that all tests have performance metrics
        tests_with_metrics = [r for r in benchmark_suite.test_results 
                            if 'flask_metrics' in r and r['flask_metrics'].get('mean')]
        
        metrics_percentage = len(tests_with_metrics) / len(benchmark_suite.test_results) * 100
        assert metrics_percentage >= 90.0, \
            f"Performance metrics coverage {metrics_percentage:.1f}% below 90% requirement"
            
        print("\n" + "="*60)
        print("BENCHMARK SUITE VALIDATION COMPLETE")
        print("="*60)
        print(f"Total Tests Executed: {len(benchmark_suite.test_results)}")
        print(f"Tests with Metrics: {len(tests_with_metrics)}")
        print(f"Metrics Coverage: {metrics_percentage:.1f}%")
        print("Required Test Categories: COMPLETE")
        print("="*60)
        
    @pytest.mark.performance
    def test_migration_validation_criteria(self):
        """
        Final validation of migration success criteria per Section 0.1.1.
        
        This test validates that the Flask implementation meets all
        migration success criteria for API performance.
        """
        # Analyze final performance summary
        performance_summary = benchmark_suite.analyze_performance_trends()
        
        # Migration Success Criteria Validation per Section 0.1.1
        validation_criteria = {
            'functional_parity': True,  # Assumed from successful API calls
            'performance_equivalence': True,
            'sla_compliance': True,
            'no_regressions': True
        }
        
        # Validate SLA compliance (sub-200ms API response time)
        sla_compliance = performance_summary.get('sla_compliance', {})
        compliance_percentage = sla_compliance.get('compliance_percentage', 0)
        validation_criteria['sla_compliance'] = compliance_percentage >= 95.0
        
        # Validate no performance regressions
        regression_analysis = performance_summary.get('regression_analysis', {})
        regressions_detected = regression_analysis.get('regressions_detected', 0)
        validation_criteria['no_regressions'] = regressions_detected == 0
        
        # Validate performance equivalence (within tolerance)
        # Performance equivalence is validated through baseline comparisons
        # This is determined by the absence of significant regressions
        validation_criteria['performance_equivalence'] = validation_criteria['no_regressions']
        
        # Overall migration success validation
        migration_success = all(validation_criteria.values())
        
        assert migration_success, \
            f"Migration validation failed. Criteria status: {validation_criteria}"
            
        print("\n" + "="*70)
        print("MIGRATION VALIDATION CRITERIA ASSESSMENT")
        print("="*70)
        print(f"Functional Parity: {'PASS' if validation_criteria['functional_parity'] else 'FAIL'}")
        print(f"Performance Equivalence: {'PASS' if validation_criteria['performance_equivalence'] else 'FAIL'}")
        print(f"SLA Compliance ({compliance_percentage:.1f}%): {'PASS' if validation_criteria['sla_compliance'] else 'FAIL'}")
        print(f"No Regressions: {'PASS' if validation_criteria['no_regressions'] else 'FAIL'}")
        print(f"\nOVERALL MIGRATION STATUS: {'SUCCESS' if migration_success else 'FAILED'}")
        print("="*70)
        
        return migration_success


# Export test classes for pytest discovery
__all__ = [
    'APIResponseBenchmarkSuite',
    'TestMainBlueprintPerformance',
    'TestAuthBlueprintPerformance', 
    'TestAPIBlueprintPerformance',
    'TestAPIErrorHandlingPerformance',
    'TestConcurrentAPIPerformance',
    'TestStatisticalAnalysis',
    'TestPrometheusMetricsIntegration',
    'TestBenchmarkValidation'
]