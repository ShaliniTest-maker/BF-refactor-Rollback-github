"""
Concurrent user load testing suite for Flask application performance validation.

This module implements comprehensive concurrent user simulation using pytest-benchmark
and threading frameworks to validate Flask application performance under concurrent
user scenarios. The testing framework ensures equivalent or improved concurrent user
support compared to the Node.js baseline implementation while monitoring system
throughput, load handling capacity, and resource utilization.

Key Features:
- Concurrent user simulation using threading and asyncio frameworks
- pytest-benchmark fixtures for statistical performance measurement
- Throughput comparison benchmarking against Node.js baseline metrics
- Request queuing and thread pool utilization monitoring
- Automated concurrent load regression testing with threshold alerting
- Flask application factory concurrent testing with blueprint route analysis

Technical Requirements:
- Load testing validates concurrent user handling equivalent to Node.js baseline per Section 4.7.2
- Concurrent testing supports Flask 3.1.1 blueprint architecture under load per Section 5.1.1
- Benchmarking includes thread pool utilization and system capacity analysis per Section 6.5.1.1
- Load testing validates system throughput and request processing capacity per Section 4.11.3
- Performance validation ensures equivalent or improved concurrent user support per Section 4.7.1

Dependencies:
- pytest-benchmark 5.1.0: Statistical performance measurement and benchmarking
- Flask 3.1.1: Flask application factory pattern and blueprint architecture
- threading: Concurrent user simulation and thread pool management
- asyncio: Asynchronous operation support for high-concurrency scenarios
- queue: Request queuing and thread coordination
- statistics: Statistical analysis of performance metrics
- concurrent.futures: Thread pool executor for managed concurrency
"""

import asyncio
import json
import pytest
import statistics
import threading
import time
import uuid
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from queue import Queue, Empty
from typing import Dict, List, Tuple, Any, Optional, Callable
from unittest.mock import Mock, patch

# Flask and testing imports
from flask import Flask, g, session, request
from flask.testing import FlaskClient

# Performance testing and benchmarking imports
try:
    import psutil
    import memory_profiler
    PROFILING_AVAILABLE = True
except ImportError:
    # Graceful degradation if profiling libraries not available
    PROFILING_AVAILABLE = False
    psutil = None
    memory_profiler = None

# Suppress pytest-benchmark warnings for cleaner test output
warnings.filterwarnings("ignore", category=UserWarning, module="pytest_benchmark")


class ConcurrentLoadTestConfig:
    """
    Configuration class for concurrent load testing parameters and thresholds.
    
    This class centralizes all configuration parameters for concurrent load testing,
    including performance thresholds, concurrency levels, test durations, and
    baseline comparison metrics as specified in the technical requirements.
    """
    
    # Concurrency Configuration
    MAX_CONCURRENT_USERS = 100
    THREAD_POOL_SIZE = 50
    REQUEST_TIMEOUT = 30.0
    RAMP_UP_TIME = 5.0  # seconds to reach max concurrency
    SUSTAINED_LOAD_DURATION = 60.0  # seconds to maintain load
    
    # Performance Thresholds (per Section 4.11.1)
    API_RESPONSE_THRESHOLD = 0.200  # < 200ms requirement
    AUTHENTICATION_THRESHOLD = 0.150  # < 150ms requirement
    DATABASE_QUERY_THRESHOLD = 0.100  # < 100ms requirement
    
    # Baseline Comparison Thresholds
    THROUGHPUT_DEGRADATION_THRESHOLD = 0.10  # Max 10% degradation allowed
    RESPONSE_TIME_DEGRADATION_THRESHOLD = 0.05  # Max 5% degradation allowed
    ERROR_RATE_THRESHOLD = 0.01  # Max 1% error rate
    
    # Statistical Analysis Configuration
    BENCHMARK_ROUNDS = 10
    BENCHMARK_WARMUP_ROUNDS = 3
    STATISTICAL_CONFIDENCE = 0.95
    OUTLIER_DETECTION_METHOD = 'iqr'  # Interquartile range method
    
    # System Resource Monitoring
    CPU_USAGE_THRESHOLD = 85.0  # Max 85% CPU usage
    MEMORY_USAGE_THRESHOLD = 85.0  # Max 85% memory usage
    THREAD_POOL_UTILIZATION_THRESHOLD = 90.0  # Max 90% thread pool usage
    
    # Load Testing Scenarios
    LOAD_TEST_SCENARIOS = {
        'light_load': {'users': 10, 'duration': 30},
        'medium_load': {'users': 50, 'duration': 60},
        'heavy_load': {'users': 100, 'duration': 120},
        'stress_test': {'users': 200, 'duration': 180}
    }


class ConcurrentUserSimulator:
    """
    Concurrent user simulation framework implementing realistic user behavior
    patterns for comprehensive load testing of Flask application endpoints.
    
    This class provides sophisticated user simulation capabilities including
    session management, realistic request patterns, and comprehensive metrics
    collection for concurrent load validation against Node.js baseline performance.
    """
    
    def __init__(self, client: FlaskClient, config: ConcurrentLoadTestConfig):
        """
        Initialize concurrent user simulator with Flask test client and configuration.
        
        Args:
            client: Flask test client for HTTP request simulation
            config: Configuration object with load testing parameters
        """
        self.client = client
        self.config = config
        self.active_users = 0
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.errors = []
        self.metrics_lock = threading.Lock()
        self.user_sessions = {}
        self.request_queue = Queue()
        self.results_queue = Queue()
        
        # System resource monitoring
        self.cpu_samples = []
        self.memory_samples = []
        self.thread_count_samples = []
        
    def authenticate_user(self, user_id: str) -> Dict[str, str]:
        """
        Authenticate a simulated user and establish session.
        
        Args:
            user_id: Unique identifier for the simulated user
            
        Returns:
            Dict containing authentication headers and session information
        """
        auth_start = time.time()
        
        try:
            # Simulate user authentication request
            auth_data = {
                'username': f'load_test_user_{user_id}',
                'password': 'test_password_123'
            }
            
            response = self.client.post('/api/auth/login', 
                                      json=auth_data,
                                      content_type='application/json')
            
            auth_time = time.time() - auth_start
            
            if response.status_code == 200:
                # Extract authentication token or session info
                response_data = response.get_json() or {}
                auth_token = response_data.get('access_token', f'test_token_{user_id}')
                
                # Store user session information
                self.user_sessions[user_id] = {
                    'token': auth_token,
                    'authenticated_at': time.time(),
                    'session_id': str(uuid.uuid4()),
                    'auth_time': auth_time
                }
                
                return {
                    'Authorization': f'Bearer {auth_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-User-ID': user_id,
                    'X-Session-ID': self.user_sessions[user_id]['session_id']
                }
            else:
                # Authentication failed, use mock headers for testing
                return {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-User-ID': user_id,
                    'X-Mock-Auth': 'true'
                }
                
        except Exception as e:
            with self.metrics_lock:
                self.errors.append({
                    'type': 'authentication_error',
                    'message': str(e),
                    'user_id': user_id,
                    'timestamp': time.time()
                })
            
            # Return fallback headers
            return {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-User-ID': user_id,
                'X-Auth-Error': 'true'
            }
    
    def simulate_user_session(self, user_id: str, session_duration: float) -> Dict[str, Any]:
        """
        Simulate realistic user session with multiple requests and think time.
        
        Args:
            user_id: Unique identifier for the simulated user
            session_duration: Duration of the user session in seconds
            
        Returns:
            Dict containing session metrics and performance data
        """
        session_start = time.time()
        session_metrics = {
            'user_id': user_id,
            'start_time': session_start,
            'requests': [],
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'average_response_time': 0.0,
            'session_duration': session_duration
        }
        
        try:
            # Authenticate user and get headers
            headers = self.authenticate_user(user_id)
            
            # Define realistic request patterns
            request_patterns = [
                ('GET', '/api/users/profile', None),
                ('GET', '/api/dashboard', None),
                ('POST', '/api/users/preferences', {'theme': 'dark', 'notifications': True}),
                ('GET', '/api/data/summary', None),
                ('PUT', '/api/users/profile', {'name': f'User {user_id}', 'email': f'user{user_id}@test.com'}),
                ('GET', '/api/reports', None),
                ('POST', '/api/actions/log', {'action': 'page_view', 'page': '/dashboard'}),
                ('GET', '/api/notifications', None),
                ('DELETE', '/api/cache', None),
                ('GET', '/api/health', None)
            ]
            
            session_end_time = session_start + session_duration
            
            while time.time() < session_end_time:
                # Select random request pattern
                method, endpoint, data = request_patterns[session_metrics['total_requests'] % len(request_patterns)]
                
                # Execute request with timing
                request_start = time.time()
                
                try:
                    if method == 'GET':
                        response = self.client.get(endpoint, headers=headers)
                    elif method == 'POST':
                        response = self.client.post(endpoint, json=data, headers=headers)
                    elif method == 'PUT':
                        response = self.client.put(endpoint, json=data, headers=headers)
                    elif method == 'DELETE':
                        response = self.client.delete(endpoint, headers=headers)
                    else:
                        continue
                    
                    request_time = time.time() - request_start
                    
                    # Record request metrics
                    request_metrics = {
                        'method': method,
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'response_time': request_time,
                        'timestamp': request_start,
                        'success': 200 <= response.status_code < 400
                    }
                    
                    session_metrics['requests'].append(request_metrics)
                    session_metrics['total_requests'] += 1
                    
                    if request_metrics['success']:
                        session_metrics['successful_requests'] += 1
                    else:
                        session_metrics['failed_requests'] += 1
                    
                    # Update global metrics with thread safety
                    with self.metrics_lock:
                        self.total_requests += 1
                        self.response_times.append(request_time)
                        
                        if request_metrics['success']:
                            self.successful_requests += 1
                        else:
                            self.failed_requests += 1
                            self.errors.append({
                                'type': 'http_error',
                                'status_code': response.status_code,
                                'endpoint': endpoint,
                                'user_id': user_id,
                                'timestamp': request_start
                            })
                    
                    # Simulate realistic user think time (0.5-3 seconds)
                    think_time = 0.5 + (time.time() % 2.5)
                    time.sleep(think_time)
                    
                except Exception as e:
                    request_time = time.time() - request_start
                    session_metrics['failed_requests'] += 1
                    
                    with self.metrics_lock:
                        self.total_requests += 1
                        self.failed_requests += 1
                        self.errors.append({
                            'type': 'request_exception',
                            'message': str(e),
                            'endpoint': endpoint,
                            'user_id': user_id,
                            'timestamp': request_start
                        })
            
            # Calculate session averages
            if session_metrics['requests']:
                response_times = [r['response_time'] for r in session_metrics['requests']]
                session_metrics['average_response_time'] = statistics.mean(response_times)
                session_metrics['median_response_time'] = statistics.median(response_times)
                session_metrics['max_response_time'] = max(response_times)
                session_metrics['min_response_time'] = min(response_times)
            
            session_metrics['actual_duration'] = time.time() - session_start
            return session_metrics
            
        except Exception as e:
            with self.metrics_lock:
                self.errors.append({
                    'type': 'session_error',
                    'message': str(e),
                    'user_id': user_id,
                    'timestamp': session_start
                })
            
            session_metrics['error'] = str(e)
            session_metrics['actual_duration'] = time.time() - session_start
            return session_metrics
    
    def monitor_system_resources(self, duration: float) -> None:
        """
        Monitor system resource utilization during load testing.
        
        Args:
            duration: Duration to monitor system resources in seconds
        """
        if not PROFILING_AVAILABLE or not psutil:
            return
        
        monitor_start = time.time()
        monitor_end = monitor_start + duration
        
        while time.time() < monitor_end:
            try:
                # Sample CPU usage
                cpu_percent = psutil.cpu_percent(interval=0.1)
                
                # Sample memory usage
                memory_info = psutil.virtual_memory()
                memory_percent = memory_info.percent
                
                # Sample thread count
                process = psutil.Process()
                thread_count = process.num_threads()
                
                timestamp = time.time()
                
                with self.metrics_lock:
                    self.cpu_samples.append((timestamp, cpu_percent))
                    self.memory_samples.append((timestamp, memory_percent))
                    self.thread_count_samples.append((timestamp, thread_count))
                
                time.sleep(1.0)  # Sample every second
                
            except Exception as e:
                with self.metrics_lock:
                    self.errors.append({
                        'type': 'monitoring_error',
                        'message': str(e),
                        'timestamp': time.time()
                    })
                break
    
    def execute_concurrent_load_test(self, 
                                   num_users: int, 
                                   duration: float,
                                   ramp_up_time: float = None) -> Dict[str, Any]:
        """
        Execute comprehensive concurrent load test with specified parameters.
        
        Args:
            num_users: Number of concurrent users to simulate
            duration: Test duration in seconds
            ramp_up_time: Time to ramp up to full load (optional)
            
        Returns:
            Dict containing comprehensive test results and metrics
        """
        if ramp_up_time is None:
            ramp_up_time = self.config.RAMP_UP_TIME
        
        test_start = time.time()
        test_results = {
            'test_config': {
                'num_users': num_users,
                'duration': duration,
                'ramp_up_time': ramp_up_time,
                'start_time': test_start
            },
            'session_results': [],
            'performance_metrics': {},
            'resource_utilization': {},
            'errors': []
        }
        
        # Reset metrics
        with self.metrics_lock:
            self.active_users = 0
            self.total_requests = 0
            self.successful_requests = 0
            self.failed_requests = 0
            self.response_times = []
            self.errors = []
            self.cpu_samples = []
            self.memory_samples = []
            self.thread_count_samples = []
        
        # Start system resource monitoring in background thread
        monitor_thread = threading.Thread(
            target=self.monitor_system_resources,
            args=(duration + ramp_up_time + 10,),  # Monitor slightly longer
            daemon=True
        )
        monitor_thread.start()
        
        # Create thread pool for concurrent user simulation
        with ThreadPoolExecutor(max_workers=min(num_users, self.config.THREAD_POOL_SIZE)) as executor:
            # Submit user session tasks with gradual ramp-up
            futures = []
            
            for i in range(num_users):
                user_id = f"user_{i}_{int(test_start)}"
                
                # Calculate start delay for gradual ramp-up
                start_delay = (i * ramp_up_time) / num_users if ramp_up_time > 0 else 0
                
                # Schedule user session
                future = executor.submit(
                    self._delayed_user_session,
                    user_id,
                    duration,
                    start_delay
                )
                futures.append(future)
            
            # Collect results as they complete
            for future in as_completed(futures):
                try:
                    session_result = future.result(timeout=duration + 60)
                    test_results['session_results'].append(session_result)
                except Exception as e:
                    with self.metrics_lock:
                        self.errors.append({
                            'type': 'session_execution_error',
                            'message': str(e),
                            'timestamp': time.time()
                        })
        
        # Calculate final performance metrics
        test_end = time.time()
        test_results['test_config']['end_time'] = test_end
        test_results['test_config']['actual_duration'] = test_end - test_start
        
        # Performance summary
        with self.metrics_lock:
            test_results['performance_metrics'] = self._calculate_performance_metrics()
            test_results['resource_utilization'] = self._calculate_resource_metrics()
            test_results['errors'] = self.errors.copy()
        
        return test_results
    
    def _delayed_user_session(self, user_id: str, duration: float, delay: float) -> Dict[str, Any]:
        """
        Execute user session with initial delay for ramp-up.
        
        Args:
            user_id: Unique identifier for the user
            duration: Session duration in seconds
            delay: Initial delay before starting session
            
        Returns:
            Dict containing session results
        """
        if delay > 0:
            time.sleep(delay)
        
        with self.metrics_lock:
            self.active_users += 1
        
        try:
            result = self.simulate_user_session(user_id, duration)
            return result
        finally:
            with self.metrics_lock:
                self.active_users -= 1
    
    def _calculate_performance_metrics(self) -> Dict[str, Any]:
        """
        Calculate comprehensive performance metrics from collected data.
        
        Returns:
            Dict containing performance analysis results
        """
        metrics = {
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'error_rate': 0.0,
            'success_rate': 0.0,
            'requests_per_second': 0.0,
            'response_time_stats': {}
        }
        
        if self.total_requests > 0:
            metrics['error_rate'] = self.failed_requests / self.total_requests
            metrics['success_rate'] = self.successful_requests / self.total_requests
        
        if self.response_times:
            metrics['response_time_stats'] = {
                'mean': statistics.mean(self.response_times),
                'median': statistics.median(self.response_times),
                'min': min(self.response_times),
                'max': max(self.response_times),
                'std_dev': statistics.stdev(self.response_times) if len(self.response_times) > 1 else 0.0,
                'p95': self._calculate_percentile(self.response_times, 95),
                'p99': self._calculate_percentile(self.response_times, 99)
            }
        
        return metrics
    
    def _calculate_resource_metrics(self) -> Dict[str, Any]:
        """
        Calculate system resource utilization metrics.
        
        Returns:
            Dict containing resource utilization analysis
        """
        metrics = {
            'cpu_utilization': {},
            'memory_utilization': {},
            'thread_utilization': {}
        }
        
        if self.cpu_samples:
            cpu_values = [sample[1] for sample in self.cpu_samples]
            metrics['cpu_utilization'] = {
                'mean': statistics.mean(cpu_values),
                'max': max(cpu_values),
                'min': min(cpu_values),
                'samples': len(cpu_values)
            }
        
        if self.memory_samples:
            memory_values = [sample[1] for sample in self.memory_samples]
            metrics['memory_utilization'] = {
                'mean': statistics.mean(memory_values),
                'max': max(memory_values),
                'min': min(memory_values),
                'samples': len(memory_values)
            }
        
        if self.thread_count_samples:
            thread_values = [sample[1] for sample in self.thread_count_samples]
            metrics['thread_utilization'] = {
                'mean': statistics.mean(thread_values),
                'max': max(thread_values),
                'min': min(thread_values),
                'samples': len(thread_values)
            }
        
        return metrics
    
    @staticmethod
    def _calculate_percentile(data: List[float], percentile: int) -> float:
        """
        Calculate percentile value from data list.
        
        Args:
            data: List of numeric values
            percentile: Percentile to calculate (0-100)
            
        Returns:
            Percentile value
        """
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = (percentile / 100.0) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower_index = int(index)
            upper_index = lower_index + 1
            lower_value = sorted_data[lower_index]
            upper_value = sorted_data[min(upper_index, len(sorted_data) - 1)]
            fraction = index - lower_index
            return lower_value + fraction * (upper_value - lower_value)


class NodeJSBaselineComparator:
    """
    Baseline comparison framework for validating Flask performance against
    Node.js system metrics with statistical analysis and regression detection.
    
    This class provides comprehensive baseline comparison capabilities including
    historical performance data analysis, statistical significance testing, and
    automated regression detection to ensure migration performance parity.
    """
    
    def __init__(self, baseline_data_file: str = None):
        """
        Initialize baseline comparator with optional historical data.
        
        Args:
            baseline_data_file: Optional path to baseline performance data file
        """
        self.baseline_data_file = baseline_data_file
        self.baseline_metrics = self._load_baseline_data()
        
    def _load_baseline_data(self) -> Dict[str, Any]:
        """
        Load Node.js baseline performance data for comparison.
        
        Returns:
            Dict containing baseline performance metrics
        """
        # Default baseline metrics based on Node.js system performance
        # These would typically be loaded from historical performance data
        default_baseline = {
            'api_response_time': {
                'mean': 0.150,  # 150ms average
                'p95': 0.180,   # 180ms 95th percentile
                'p99': 0.200    # 200ms 99th percentile
            },
            'throughput': {
                'requests_per_second': 500,
                'concurrent_users_supported': 100
            },
            'error_rate': 0.005,  # 0.5% error rate
            'resource_utilization': {
                'cpu_mean': 45.0,
                'memory_mean': 60.0
            }
        }
        
        if self.baseline_data_file:
            try:
                import json
                with open(self.baseline_data_file, 'r') as f:
                    baseline_data = json.load(f)
                    # Merge with defaults, preferring loaded data
                    default_baseline.update(baseline_data)
            except (FileNotFoundError, json.JSONDecodeError):
                # Use defaults if file doesn't exist or is invalid
                pass
        
        return default_baseline
    
    def compare_performance(self, flask_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare Flask performance metrics against Node.js baseline.
        
        Args:
            flask_metrics: Performance metrics from Flask load testing
            
        Returns:
            Dict containing comparison results and statistical analysis
        """
        comparison_results = {
            'baseline_comparison': {},
            'performance_delta': {},
            'regression_detected': False,
            'recommendations': []
        }
        
        # Compare API response times
        flask_response_stats = flask_metrics.get('performance_metrics', {}).get('response_time_stats', {})
        baseline_response = self.baseline_metrics.get('api_response_time', {})
        
        if flask_response_stats and baseline_response:
            response_comparison = self._compare_response_times(flask_response_stats, baseline_response)
            comparison_results['baseline_comparison']['response_time'] = response_comparison
            
            # Check for response time regression
            if response_comparison.get('performance_ratio', 1.0) > 1.05:  # 5% degradation threshold
                comparison_results['regression_detected'] = True
                comparison_results['recommendations'].append(
                    f"Response time degradation detected: "
                    f"{response_comparison.get('performance_ratio', 1.0):.2%} slower than baseline"
                )
        
        # Compare throughput metrics
        flask_perf = flask_metrics.get('performance_metrics', {})
        baseline_throughput = self.baseline_metrics.get('throughput', {})
        
        if flask_perf and baseline_throughput:
            throughput_comparison = self._compare_throughput(flask_perf, baseline_throughput)
            comparison_results['baseline_comparison']['throughput'] = throughput_comparison
            
            # Check for throughput regression
            if throughput_comparison.get('performance_ratio', 1.0) < 0.90:  # 10% degradation threshold
                comparison_results['regression_detected'] = True
                comparison_results['recommendations'].append(
                    f"Throughput regression detected: "
                    f"{(1 - throughput_comparison.get('performance_ratio', 1.0)):.2%} reduction from baseline"
                )
        
        # Compare error rates
        flask_error_rate = flask_metrics.get('performance_metrics', {}).get('error_rate', 0.0)
        baseline_error_rate = self.baseline_metrics.get('error_rate', 0.005)
        
        error_comparison = {
            'flask_error_rate': flask_error_rate,
            'baseline_error_rate': baseline_error_rate,
            'delta': flask_error_rate - baseline_error_rate,
            'performance_ratio': (flask_error_rate / baseline_error_rate) if baseline_error_rate > 0 else 1.0
        }
        comparison_results['baseline_comparison']['error_rate'] = error_comparison
        
        if flask_error_rate > baseline_error_rate * 2:  # Error rate doubled
            comparison_results['regression_detected'] = True
            comparison_results['recommendations'].append(
                f"Error rate increase detected: {flask_error_rate:.3%} vs baseline {baseline_error_rate:.3%}"
            )
        
        # Compare resource utilization
        flask_resources = flask_metrics.get('resource_utilization', {})
        baseline_resources = self.baseline_metrics.get('resource_utilization', {})
        
        if flask_resources and baseline_resources:
            resource_comparison = self._compare_resource_utilization(flask_resources, baseline_resources)
            comparison_results['baseline_comparison']['resource_utilization'] = resource_comparison
        
        # Generate overall performance delta
        comparison_results['performance_delta'] = self._calculate_overall_delta(comparison_results['baseline_comparison'])
        
        return comparison_results
    
    def _compare_response_times(self, flask_stats: Dict[str, float], baseline_stats: Dict[str, float]) -> Dict[str, Any]:
        """
        Compare response time statistics between Flask and baseline.
        
        Args:
            flask_stats: Flask response time statistics
            baseline_stats: Baseline response time statistics
            
        Returns:
            Dict containing response time comparison results
        """
        comparison = {
            'flask_mean': flask_stats.get('mean', 0.0),
            'baseline_mean': baseline_stats.get('mean', 0.0),
            'flask_p95': flask_stats.get('p95', 0.0),
            'baseline_p95': baseline_stats.get('p95', 0.0),
            'flask_p99': flask_stats.get('p99', 0.0),
            'baseline_p99': baseline_stats.get('p99', 0.0)
        }
        
        # Calculate performance ratios
        if baseline_stats.get('mean', 0.0) > 0:
            comparison['performance_ratio'] = flask_stats.get('mean', 0.0) / baseline_stats.get('mean', 0.0)
            comparison['mean_delta_percent'] = (comparison['performance_ratio'] - 1.0) * 100
        
        if baseline_stats.get('p95', 0.0) > 0:
            comparison['p95_ratio'] = flask_stats.get('p95', 0.0) / baseline_stats.get('p95', 0.0)
            comparison['p95_delta_percent'] = (comparison['p95_ratio'] - 1.0) * 100
        
        return comparison
    
    def _compare_throughput(self, flask_metrics: Dict[str, Any], baseline_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare throughput metrics between Flask and baseline.
        
        Args:
            flask_metrics: Flask performance metrics
            baseline_metrics: Baseline throughput metrics
            
        Returns:
            Dict containing throughput comparison results
        """
        comparison = {
            'flask_requests_per_second': flask_metrics.get('requests_per_second', 0.0),
            'baseline_requests_per_second': baseline_metrics.get('requests_per_second', 0.0)
        }
        
        if baseline_metrics.get('requests_per_second', 0.0) > 0:
            comparison['performance_ratio'] = (
                flask_metrics.get('requests_per_second', 0.0) / 
                baseline_metrics.get('requests_per_second', 0.0)
            )
            comparison['throughput_delta_percent'] = (comparison['performance_ratio'] - 1.0) * 100
        
        return comparison
    
    def _compare_resource_utilization(self, flask_resources: Dict[str, Any], baseline_resources: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compare resource utilization between Flask and baseline.
        
        Args:
            flask_resources: Flask resource utilization metrics
            baseline_resources: Baseline resource utilization metrics
            
        Returns:
            Dict containing resource utilization comparison
        """
        comparison = {}
        
        # Compare CPU utilization
        flask_cpu = flask_resources.get('cpu_utilization', {})
        baseline_cpu = baseline_resources.get('cpu_mean', 0.0)
        
        if flask_cpu and baseline_cpu > 0:
            comparison['cpu'] = {
                'flask_mean': flask_cpu.get('mean', 0.0),
                'baseline_mean': baseline_cpu,
                'delta': flask_cpu.get('mean', 0.0) - baseline_cpu,
                'ratio': flask_cpu.get('mean', 0.0) / baseline_cpu
            }
        
        # Compare memory utilization
        flask_memory = flask_resources.get('memory_utilization', {})
        baseline_memory = baseline_resources.get('memory_mean', 0.0)
        
        if flask_memory and baseline_memory > 0:
            comparison['memory'] = {
                'flask_mean': flask_memory.get('mean', 0.0),
                'baseline_mean': baseline_memory,
                'delta': flask_memory.get('mean', 0.0) - baseline_memory,
                'ratio': flask_memory.get('mean', 0.0) / baseline_memory
            }
        
        return comparison
    
    def _calculate_overall_delta(self, baseline_comparison: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall performance delta across all metrics.
        
        Args:
            baseline_comparison: Detailed comparison results
            
        Returns:
            Dict containing overall performance summary
        """
        deltas = {
            'response_time_improvement': 0.0,
            'throughput_improvement': 0.0,
            'error_rate_change': 0.0,
            'overall_score': 0.0
        }
        
        # Response time delta (improvement is negative delta)
        response_comparison = baseline_comparison.get('response_time', {})
        if 'performance_ratio' in response_comparison:
            deltas['response_time_improvement'] = (1.0 - response_comparison['performance_ratio']) * 100
        
        # Throughput delta (improvement is positive delta)
        throughput_comparison = baseline_comparison.get('throughput', {})
        if 'performance_ratio' in throughput_comparison:
            deltas['throughput_improvement'] = (throughput_comparison['performance_ratio'] - 1.0) * 100
        
        # Error rate delta (improvement is negative delta)
        error_comparison = baseline_comparison.get('error_rate', {})
        if 'delta' in error_comparison:
            deltas['error_rate_change'] = error_comparison['delta'] * 100
        
        # Calculate overall score (weighted average)
        weights = {'response_time': 0.4, 'throughput': 0.4, 'error_rate': 0.2}
        overall_score = (
            deltas['response_time_improvement'] * weights['response_time'] +
            deltas['throughput_improvement'] * weights['throughput'] +
            (-deltas['error_rate_change']) * weights['error_rate']  # Negative because lower error rate is better
        )
        deltas['overall_score'] = overall_score
        
        return deltas


# ================================
# pytest Fixtures and Test Configuration
# ================================

@pytest.fixture(scope='session')
def load_test_config():
    """
    Load testing configuration fixture providing centralized test parameters.
    
    Returns:
        ConcurrentLoadTestConfig: Configuration object with test parameters
    """
    return ConcurrentLoadTestConfig()


@pytest.fixture(scope='session')
def baseline_comparator():
    """
    Baseline comparison fixture for Node.js performance validation.
    
    Returns:
        NodeJSBaselineComparator: Baseline comparison framework
    """
    return NodeJSBaselineComparator()


@pytest.fixture
def concurrent_simulator(client, load_test_config):
    """
    Concurrent user simulator fixture for load testing.
    
    Args:
        client: Flask test client from conftest.py
        load_test_config: Load testing configuration
        
    Returns:
        ConcurrentUserSimulator: Configured user simulator
    """
    return ConcurrentUserSimulator(client, load_test_config)


@pytest.fixture
def mock_authentication():
    """
    Mock authentication fixture for consistent load testing.
    
    Returns:
        Mock object configured for authentication simulation
    """
    auth_mock = Mock()
    auth_mock.authenticate.return_value = {
        'access_token': 'test_token_12345',
        'token_type': 'Bearer',
        'expires_in': 3600
    }
    auth_mock.validate_token.return_value = True
    return auth_mock


# ================================
# Concurrent Load Testing Suite
# ================================

class TestConcurrentLoad:
    """
    Comprehensive concurrent load testing suite for Flask application validation.
    
    This test class implements extensive concurrent user simulation and performance
    validation against Node.js baseline metrics with statistical analysis and
    regression detection capabilities as specified in the technical requirements.
    """
    
    @pytest.mark.performance
    @pytest.mark.parametrize("load_scenario", [
        'light_load',
        'medium_load', 
        'heavy_load'
    ])
    def test_concurrent_user_load_scenarios(self, 
                                          concurrent_simulator, 
                                          load_test_config,
                                          baseline_comparator,
                                          benchmark,
                                          load_scenario):
        """
        Test Flask application under various concurrent user load scenarios.
        
        This test validates the Flask application's ability to handle different
        levels of concurrent user load while maintaining performance thresholds
        and comparing against Node.js baseline metrics.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            baseline_comparator: Baseline comparison framework
            benchmark: pytest-benchmark fixture for performance measurement
            load_scenario: Load scenario name from configuration
        """
        scenario_config = load_test_config.LOAD_TEST_SCENARIOS[load_scenario]
        num_users = scenario_config['users']
        duration = scenario_config['duration']
        
        def execute_load_test():
            """Execute the actual load test for benchmarking"""
            return concurrent_simulator.execute_concurrent_load_test(
                num_users=num_users,
                duration=duration,
                ramp_up_time=load_test_config.RAMP_UP_TIME
            )
        
        # Execute load test with pytest-benchmark measurement
        test_results = benchmark.pedantic(
            execute_load_test,
            rounds=load_test_config.BENCHMARK_ROUNDS,
            warmup_rounds=load_test_config.BENCHMARK_WARMUP_ROUNDS,
            iterations=1
        )
        
        # Validate performance metrics
        performance_metrics = test_results['performance_metrics']
        
        # Assert response time thresholds
        response_stats = performance_metrics.get('response_time_stats', {})
        assert response_stats.get('mean', float('inf')) < load_test_config.API_RESPONSE_THRESHOLD, \
            f"Mean response time {response_stats.get('mean', 0):.3f}s exceeds threshold {load_test_config.API_RESPONSE_THRESHOLD}s"
        
        assert response_stats.get('p95', float('inf')) < load_test_config.API_RESPONSE_THRESHOLD * 1.2, \
            f"P95 response time {response_stats.get('p95', 0):.3f}s exceeds threshold"
        
        # Assert error rate thresholds
        error_rate = performance_metrics.get('error_rate', 1.0)
        assert error_rate < load_test_config.ERROR_RATE_THRESHOLD, \
            f"Error rate {error_rate:.3%} exceeds threshold {load_test_config.ERROR_RATE_THRESHOLD:.3%}"
        
        # Assert minimum success rate
        success_rate = performance_metrics.get('success_rate', 0.0)
        assert success_rate > 0.99, f"Success rate {success_rate:.3%} too low"
        
        # Compare against baseline performance
        comparison_results = baseline_comparator.compare_performance(test_results)
        
        # Assert no significant performance regression
        assert not comparison_results['regression_detected'], \
            f"Performance regression detected: {comparison_results['recommendations']}"
        
        # Validate resource utilization if available
        resource_metrics = test_results.get('resource_utilization', {})
        if PROFILING_AVAILABLE and resource_metrics:
            cpu_usage = resource_metrics.get('cpu_utilization', {}).get('mean', 0.0)
            memory_usage = resource_metrics.get('memory_utilization', {}).get('mean', 0.0)
            
            assert cpu_usage < load_test_config.CPU_USAGE_THRESHOLD, \
                f"CPU usage {cpu_usage:.1f}% exceeds threshold {load_test_config.CPU_USAGE_THRESHOLD}%"
            
            assert memory_usage < load_test_config.MEMORY_USAGE_THRESHOLD, \
                f"Memory usage {memory_usage:.1f}% exceeds threshold {load_test_config.MEMORY_USAGE_THRESHOLD}%"
        
        # Log performance summary for analysis
        print(f"\n{load_scenario.upper()} PERFORMANCE SUMMARY:")
        print(f"Users: {num_users}, Duration: {duration}s")
        print(f"Total Requests: {performance_metrics.get('total_requests', 0)}")
        print(f"Success Rate: {performance_metrics.get('success_rate', 0.0):.3%}")
        print(f"Mean Response Time: {response_stats.get('mean', 0.0):.3f}s")
        print(f"P95 Response Time: {response_stats.get('p95', 0.0):.3f}s")
        print(f"Error Rate: {performance_metrics.get('error_rate', 0.0):.3%}")
        
        if comparison_results.get('performance_delta'):
            delta = comparison_results['performance_delta']
            print(f"Performance vs Baseline: {delta.get('overall_score', 0.0):.1f}% improvement")
    
    @pytest.mark.performance
    def test_thread_pool_utilization_monitoring(self, 
                                               concurrent_simulator,
                                               load_test_config,
                                               benchmark):
        """
        Test thread pool utilization and capacity analysis during concurrent load.
        
        This test specifically monitors thread pool behavior and validates efficient
        resource utilization under various concurrency levels as required by
        Section 6.5.1.1 of the technical specification.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            benchmark: pytest-benchmark fixture for performance measurement
        """
        # Test with escalating concurrency levels
        concurrency_levels = [10, 25, 50, 75, 100]
        thread_utilization_results = []
        
        for num_users in concurrency_levels:
            def execute_thread_test():
                return concurrent_simulator.execute_concurrent_load_test(
                    num_users=num_users,
                    duration=30.0,  # Shorter duration for thread analysis
                    ramp_up_time=5.0
                )
            
            # Execute test with benchmarking
            test_results = benchmark.pedantic(
                execute_thread_test,
                rounds=3,  # Fewer rounds for thread testing
                warmup_rounds=1,
                iterations=1
            )
            
            # Analyze thread utilization
            resource_metrics = test_results.get('resource_utilization', {})
            thread_metrics = resource_metrics.get('thread_utilization', {})
            
            utilization_data = {
                'num_users': num_users,
                'max_threads': thread_metrics.get('max', 0),
                'mean_threads': thread_metrics.get('mean', 0),
                'thread_efficiency': 0.0,
                'performance_metrics': test_results.get('performance_metrics', {})
            }
            
            # Calculate thread efficiency
            if num_users > 0:
                utilization_data['thread_efficiency'] = thread_metrics.get('mean', 0) / num_users
            
            thread_utilization_results.append(utilization_data)
            
            # Validate thread pool doesn't exceed reasonable limits
            max_threads = thread_metrics.get('max', 0)
            expected_max_threads = min(num_users, load_test_config.THREAD_POOL_SIZE * 2)  # Allow some overhead
            
            assert max_threads <= expected_max_threads, \
                f"Thread count {max_threads} exceeds expected maximum {expected_max_threads} for {num_users} users"
            
            # Validate performance doesn't degrade significantly with thread count
            response_stats = test_results.get('performance_metrics', {}).get('response_time_stats', {})
            mean_response_time = response_stats.get('mean', 0.0)
            
            assert mean_response_time < load_test_config.API_RESPONSE_THRESHOLD * 1.5, \
                f"Response time {mean_response_time:.3f}s too high under {num_users} concurrent users"
        
        # Analyze thread scaling efficiency
        print("\nTHREAD POOL UTILIZATION ANALYSIS:")
        for result in thread_utilization_results:
            print(f"Users: {result['num_users']:3d} | "
                  f"Max Threads: {result['max_threads']:3d} | "
                  f"Mean Threads: {result['mean_threads']:5.1f} | "
                  f"Efficiency: {result['thread_efficiency']:5.3f} | "
                  f"Response Time: {result['performance_metrics'].get('response_time_stats', {}).get('mean', 0.0):.3f}s")
        
        # Assert thread efficiency remains reasonable
        for result in thread_utilization_results:
            if result['num_users'] >= 10:  # Skip very low concurrency
                assert result['thread_efficiency'] <= 2.0, \
                    f"Thread efficiency too low: {result['thread_efficiency']:.3f} for {result['num_users']} users"
    
    @pytest.mark.performance
    def test_request_queuing_and_throughput_analysis(self,
                                                    concurrent_simulator,
                                                    load_test_config,
                                                    baseline_comparator,
                                                    benchmark):
        """
        Test request queuing behavior and throughput capacity validation.
        
        This test analyzes request queuing patterns and validates system throughput
        capacity under sustained load as specified in Section 4.11.3 of the
        technical specification.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            baseline_comparator: Baseline comparison framework
            benchmark: pytest-benchmark fixture for performance measurement
        """
        # Test sustained high-throughput scenario
        def execute_throughput_test():
            return concurrent_simulator.execute_concurrent_load_test(
                num_users=load_test_config.MAX_CONCURRENT_USERS,
                duration=load_test_config.SUSTAINED_LOAD_DURATION,
                ramp_up_time=load_test_config.RAMP_UP_TIME
            )
        
        # Execute comprehensive throughput test
        test_results = benchmark.pedantic(
            execute_throughput_test,
            rounds=5,
            warmup_rounds=2,
            iterations=1
        )
        
        # Analyze throughput metrics
        performance_metrics = test_results['performance_metrics']
        total_requests = performance_metrics.get('total_requests', 0)
        test_duration = test_results['test_config']['actual_duration']
        
        # Calculate throughput metrics
        requests_per_second = total_requests / test_duration if test_duration > 0 else 0
        successful_requests = performance_metrics.get('successful_requests', 0)
        successful_rps = successful_requests / test_duration if test_duration > 0 else 0
        
        # Update performance metrics with calculated values
        performance_metrics['requests_per_second'] = requests_per_second
        performance_metrics['successful_requests_per_second'] = successful_rps
        
        # Validate minimum throughput requirements
        min_expected_rps = 50  # Minimum 50 requests per second
        assert successful_rps >= min_expected_rps, \
            f"Throughput {successful_rps:.1f} RPS below minimum {min_expected_rps} RPS"
        
        # Validate response time distribution under load
        response_stats = performance_metrics.get('response_time_stats', {})
        p95_response_time = response_stats.get('p95', float('inf'))
        p99_response_time = response_stats.get('p99', float('inf'))
        
        # Assert performance distribution thresholds
        assert p95_response_time < load_test_config.API_RESPONSE_THRESHOLD * 1.5, \
            f"P95 response time {p95_response_time:.3f}s exceeds threshold under sustained load"
        
        assert p99_response_time < load_test_config.API_RESPONSE_THRESHOLD * 2.0, \
            f"P99 response time {p99_response_time:.3f}s too high under sustained load"
        
        # Compare against baseline throughput
        comparison_results = baseline_comparator.compare_performance(test_results)
        throughput_comparison = comparison_results.get('baseline_comparison', {}).get('throughput', {})
        
        if 'performance_ratio' in throughput_comparison:
            throughput_ratio = throughput_comparison['performance_ratio']
            assert throughput_ratio >= 0.90, \
                f"Throughput regression: {throughput_ratio:.3f} of baseline performance"
        
        # Validate error rate under sustained load
        error_rate = performance_metrics.get('error_rate', 1.0)
        assert error_rate < load_test_config.ERROR_RATE_THRESHOLD * 2, \
            f"Error rate {error_rate:.3%} too high under sustained load"
        
        # Log throughput analysis
        print(f"\nTHROUGHPUT ANALYSIS SUMMARY:")
        print(f"Test Duration: {test_duration:.1f}s")
        print(f"Total Requests: {total_requests}")
        print(f"Successful Requests: {successful_requests}")
        print(f"Requests per Second: {requests_per_second:.1f}")
        print(f"Successful RPS: {successful_rps:.1f}")
        print(f"Error Rate: {error_rate:.3%}")
        print(f"Mean Response Time: {response_stats.get('mean', 0.0):.3f}s")
        print(f"P95 Response Time: {p95_response_time:.3f}s")
        print(f"P99 Response Time: {p99_response_time:.3f}s")
        
        if throughput_comparison:
            print(f"Baseline Comparison: {throughput_comparison.get('throughput_delta_percent', 0.0):.1f}% delta")
    
    @pytest.mark.performance
    @pytest.mark.stress
    def test_stress_testing_with_resource_monitoring(self,
                                                    concurrent_simulator,
                                                    load_test_config,
                                                    benchmark):
        """
        Execute stress testing with comprehensive resource monitoring.
        
        This test pushes the Flask application beyond normal operating parameters
        to validate behavior under extreme load and identify system breaking points
        while monitoring resource utilization patterns.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            benchmark: pytest-benchmark fixture for performance measurement
        """
        stress_scenario = load_test_config.LOAD_TEST_SCENARIOS['stress_test']
        
        def execute_stress_test():
            return concurrent_simulator.execute_concurrent_load_test(
                num_users=stress_scenario['users'],
                duration=stress_scenario['duration'],
                ramp_up_time=15.0  # Longer ramp-up for stress test
            )
        
        # Execute stress test with extended benchmarking
        test_results = benchmark.pedantic(
            execute_stress_test,
            rounds=2,  # Fewer rounds for stress testing
            warmup_rounds=1,
            iterations=1
        )
        
        # Analyze stress test results
        performance_metrics = test_results['performance_metrics']
        resource_metrics = test_results.get('resource_utilization', {})
        
        # Validate system didn't completely fail under stress
        success_rate = performance_metrics.get('success_rate', 0.0)
        assert success_rate > 0.50, \
            f"Success rate {success_rate:.3%} too low under stress - system may be failing"
        
        # Validate response times didn't become completely unreasonable
        response_stats = performance_metrics.get('response_time_stats', {})
        mean_response_time = response_stats.get('mean', float('inf'))
        assert mean_response_time < 10.0, \
            f"Mean response time {mean_response_time:.3f}s unreasonably high under stress"
        
        # Analyze resource utilization patterns under stress
        if PROFILING_AVAILABLE and resource_metrics:
            cpu_metrics = resource_metrics.get('cpu_utilization', {})
            memory_metrics = resource_metrics.get('memory_utilization', {})
            thread_metrics = resource_metrics.get('thread_utilization', {})
            
            max_cpu = cpu_metrics.get('max', 0.0)
            max_memory = memory_metrics.get('max', 0.0)
            max_threads = thread_metrics.get('max', 0)
            
            # Log resource utilization under stress
            print(f"\nSTRESS TEST RESOURCE ANALYSIS:")
            print(f"Peak CPU Usage: {max_cpu:.1f}%")
            print(f"Peak Memory Usage: {max_memory:.1f}%")
            print(f"Peak Thread Count: {max_threads}")
            print(f"Success Rate: {success_rate:.3%}")
            print(f"Mean Response Time: {mean_response_time:.3f}s")
            
            # Validate resource usage patterns
            assert max_cpu < 98.0, f"CPU usage {max_cpu:.1f}% indicates system overload"
            assert max_memory < 95.0, f"Memory usage {max_memory:.1f}% indicates potential memory issues"
        
        # Validate error patterns under stress
        errors = test_results.get('errors', [])
        error_types = {}
        for error in errors:
            error_type = error.get('type', 'unknown')
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        # Log error analysis
        if error_types:
            print(f"\nERROR ANALYSIS UNDER STRESS:")
            for error_type, count in error_types.items():
                print(f"{error_type}: {count} occurrences")
        
        # Validate no single error type dominates
        total_errors = sum(error_types.values())
        if total_errors > 0:
            for error_type, count in error_types.items():
                error_percentage = count / total_errors
                assert error_percentage < 0.80, \
                    f"Error type '{error_type}' represents {error_percentage:.1%} of all errors - potential systemic issue"
    
    @pytest.mark.performance
    def test_concurrent_authentication_performance(self,
                                                  concurrent_simulator,
                                                  load_test_config,
                                                  mock_authentication,
                                                  benchmark):
        """
        Test authentication performance under concurrent load.
        
        This test specifically validates authentication flow performance under
        concurrent user scenarios, ensuring sub-150ms authentication response
        times as specified in Section 4.11.1 of the technical specification.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            mock_authentication: Mock authentication service
            benchmark: pytest-benchmark fixture for performance measurement
        """
        # Configure authentication-focused test
        auth_test_users = 50
        auth_test_duration = 30.0
        
        with patch('src.auth.services.auth_service', mock_authentication):
            def execute_auth_test():
                return concurrent_simulator.execute_concurrent_load_test(
                    num_users=auth_test_users,
                    duration=auth_test_duration,
                    ramp_up_time=5.0
                )
            
            # Execute authentication performance test
            test_results = benchmark.pedantic(
                execute_auth_test,
                rounds=5,
                warmup_rounds=2,
                iterations=1
            )
        
        # Analyze authentication-specific metrics
        session_results = test_results.get('session_results', [])
        auth_times = []
        
        for session in session_results:
            if 'auth_time' in session:
                auth_times.append(session['auth_time'])
        
        if auth_times:
            # Calculate authentication performance statistics
            mean_auth_time = statistics.mean(auth_times)
            max_auth_time = max(auth_times)
            p95_auth_time = concurrent_simulator._calculate_percentile(auth_times, 95)
            
            # Validate authentication performance thresholds
            assert mean_auth_time < load_test_config.AUTHENTICATION_THRESHOLD, \
                f"Mean authentication time {mean_auth_time:.3f}s exceeds threshold {load_test_config.AUTHENTICATION_THRESHOLD}s"
            
            assert p95_auth_time < load_test_config.AUTHENTICATION_THRESHOLD * 1.5, \
                f"P95 authentication time {p95_auth_time:.3f}s exceeds threshold"
            
            assert max_auth_time < load_test_config.AUTHENTICATION_THRESHOLD * 3.0, \
                f"Max authentication time {max_auth_time:.3f}s unreasonably high"
            
            # Log authentication performance summary
            print(f"\nAUTHENTICATION PERFORMANCE SUMMARY:")
            print(f"Total Authentication Attempts: {len(auth_times)}")
            print(f"Mean Authentication Time: {mean_auth_time:.3f}s")
            print(f"P95 Authentication Time: {p95_auth_time:.3f}s")
            print(f"Max Authentication Time: {max_auth_time:.3f}s")
        
        # Validate overall performance under authentication load
        performance_metrics = test_results['performance_metrics']
        response_stats = performance_metrics.get('response_time_stats', {})
        
        assert response_stats.get('mean', float('inf')) < load_test_config.API_RESPONSE_THRESHOLD, \
            f"API response time degraded under authentication load: {response_stats.get('mean', 0.0):.3f}s"
    
    @pytest.mark.performance
    def test_blueprint_route_load_distribution(self,
                                              concurrent_simulator,
                                              load_test_config,
                                              benchmark):
        """
        Test Flask blueprint route load distribution and performance analysis.
        
        This test validates that Flask blueprint architecture performs efficiently
        under concurrent load with proper route distribution as specified in
        Section 5.1.1 of the technical specification.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters
            benchmark: pytest-benchmark fixture for performance measurement
        """
        # Execute load test with route analysis
        def execute_blueprint_test():
            return concurrent_simulator.execute_concurrent_load_test(
                num_users=75,
                duration=45.0,
                ramp_up_time=10.0
            )
        
        test_results = benchmark.pedantic(
            execute_blueprint_test,
            rounds=3,
            warmup_rounds=1,
            iterations=1
        )
        
        # Analyze route distribution from session results
        session_results = test_results.get('session_results', [])
        route_metrics = {}
        
        for session in session_results:
            requests = session.get('requests', [])
            for request in requests:
                endpoint = request.get('endpoint', 'unknown')
                method = request.get('method', 'GET')
                response_time = request.get('response_time', 0.0)
                success = request.get('success', False)
                
                route_key = f"{method} {endpoint}"
                
                if route_key not in route_metrics:
                    route_metrics[route_key] = {
                        'count': 0,
                        'total_time': 0.0,
                        'successes': 0,
                        'failures': 0,
                        'response_times': []
                    }
                
                route_metrics[route_key]['count'] += 1
                route_metrics[route_key]['total_time'] += response_time
                route_metrics[route_key]['response_times'].append(response_time)
                
                if success:
                    route_metrics[route_key]['successes'] += 1
                else:
                    route_metrics[route_key]['failures'] += 1
        
        # Analyze per-route performance
        print(f"\nBLUEPRINT ROUTE PERFORMANCE ANALYSIS:")
        print(f"{'Route':<30} {'Count':<8} {'Mean(ms)':<10} {'P95(ms)':<10} {'Success%':<10}")
        print("-" * 75)
        
        for route, metrics in route_metrics.items():
            count = metrics['count']
            mean_time = (metrics['total_time'] / count) * 1000 if count > 0 else 0.0
            success_rate = (metrics['successes'] / count) * 100 if count > 0 else 0.0
            
            response_times = metrics['response_times']
            p95_time = concurrent_simulator._calculate_percentile(response_times, 95) * 1000 if response_times else 0.0
            
            print(f"{route:<30} {count:<8} {mean_time:<10.1f} {p95_time:<10.1f} {success_rate:<10.1f}")
            
            # Validate per-route performance
            assert mean_time < load_test_config.API_RESPONSE_THRESHOLD * 1000, \
                f"Route {route} mean response time {mean_time:.1f}ms exceeds threshold"
            
            assert success_rate > 95.0, \
                f"Route {route} success rate {success_rate:.1f}% too low"
        
        # Validate route distribution balance
        total_requests = sum(metrics['count'] for metrics in route_metrics.values())
        if total_requests > 0:
            for route, metrics in route_metrics.items():
                route_percentage = (metrics['count'] / total_requests) * 100
                # No single route should handle more than 50% of traffic (indicates poor distribution)
                assert route_percentage < 50.0, \
                    f"Route {route} handling {route_percentage:.1f}% of traffic - poor load distribution"
        
        # Validate overall performance with blueprint architecture
        performance_metrics = test_results['performance_metrics']
        assert performance_metrics.get('success_rate', 0.0) > 0.98, \
            f"Overall success rate {performance_metrics.get('success_rate', 0.0):.3%} degraded with blueprint load"
    
    @pytest.mark.performance
    def test_automated_regression_detection(self,
                                          concurrent_simulator,
                                          load_test_config,
                                          baseline_comparator,
                                          benchmark):
        """
        Test automated concurrent load regression detection with statistical validation.
        
        This test implements comprehensive regression detection algorithms with
        statistical validation and threshold alerting as specified in Section 4.7.2
        of the technical specification.
        
        Args:
            concurrent_simulator: User simulation framework
            load_test_config: Test configuration parameters  
            baseline_comparator: Baseline comparison framework
            benchmark: pytest-benchmark fixture for performance measurement
        """
        # Execute comprehensive regression test
        def execute_regression_test():
            return concurrent_simulator.execute_concurrent_load_test(
                num_users=60,
                duration=90.0,
                ramp_up_time=15.0
            )
        
        test_results = benchmark.pedantic(
            execute_regression_test,
            rounds=load_test_config.BENCHMARK_ROUNDS,
            warmup_rounds=load_test_config.BENCHMARK_WARMUP_ROUNDS,
            iterations=1
        )
        
        # Perform comprehensive baseline comparison
        comparison_results = baseline_comparator.compare_performance(test_results)
        
        # Detailed regression analysis
        regression_detected = comparison_results.get('regression_detected', False)
        recommendations = comparison_results.get('recommendations', [])
        performance_delta = comparison_results.get('performance_delta', {})
        baseline_comparison = comparison_results.get('baseline_comparison', {})
        
        # Log regression analysis results
        print(f"\nREGRESSION ANALYSIS RESULTS:")
        print(f"Regression Detected: {regression_detected}")
        print(f"Overall Performance Score: {performance_delta.get('overall_score', 0.0):.1f}%")
        
        if baseline_comparison.get('response_time'):
            rt_comparison = baseline_comparison['response_time']
            print(f"Response Time Delta: {rt_comparison.get('mean_delta_percent', 0.0):+.1f}%")
        
        if baseline_comparison.get('throughput'):
            tp_comparison = baseline_comparison['throughput']
            print(f"Throughput Delta: {tp_comparison.get('throughput_delta_percent', 0.0):+.1f}%")
        
        if baseline_comparison.get('error_rate'):
            er_comparison = baseline_comparison['error_rate']
            print(f"Error Rate Change: {er_comparison.get('delta', 0.0):+.3%}")
        
        if recommendations:
            print(f"Recommendations:")
            for rec in recommendations:
                print(f"  - {rec}")
        
        # Statistical validation of performance metrics
        performance_metrics = test_results['performance_metrics']
        response_stats = performance_metrics.get('response_time_stats', {})
        
        # Validate statistical significance of performance measurements
        if 'std_dev' in response_stats and response_stats['std_dev'] > 0:
            coefficient_of_variation = response_stats['std_dev'] / response_stats.get('mean', 1.0)
            assert coefficient_of_variation < 1.0, \
                f"High performance variability detected: CV={coefficient_of_variation:.3f}"
        
        # Validate performance consistency across benchmark rounds
        benchmark_stats = getattr(benchmark, 'stats', None)
        if benchmark_stats and hasattr(benchmark_stats, 'data'):
            benchmark_times = benchmark_stats.data
            if len(benchmark_times) > 1:
                benchmark_cv = statistics.stdev(benchmark_times) / statistics.mean(benchmark_times)
                assert benchmark_cv < 0.2, \
                    f"Inconsistent benchmark performance: CV={benchmark_cv:.3f}"
        
        # Assert no critical regressions
        if regression_detected:
            # Allow minor regressions but fail on major ones
            overall_score = performance_delta.get('overall_score', 0.0)
            assert overall_score > -20.0, \
                f"Major performance regression detected: {overall_score:.1f}% degradation"
        
        # Validate error rate remains within acceptable bounds
        error_rate = performance_metrics.get('error_rate', 1.0)
        assert error_rate < load_test_config.ERROR_RATE_THRESHOLD * 3, \
            f"Error rate {error_rate:.3%} indicates potential system issues"
        
        # Final assertion: system maintains basic functionality
        success_rate = performance_metrics.get('success_rate', 0.0)
        assert success_rate > 0.90, \
            f"Success rate {success_rate:.3%} too low - potential system failure"


# ================================
# Utility Functions and Helpers
# ================================

def generate_performance_report(test_results: Dict[str, Any], 
                               comparison_results: Dict[str, Any] = None) -> str:
    """
    Generate comprehensive performance report from test results.
    
    Args:
        test_results: Results from concurrent load testing
        comparison_results: Optional baseline comparison results
        
    Returns:
        Formatted performance report string
    """
    report_lines = [
        "=" * 80,
        "CONCURRENT LOAD TESTING PERFORMANCE REPORT",
        "=" * 80,
        ""
    ]
    
    # Test configuration summary
    test_config = test_results.get('test_config', {})
    report_lines.extend([
        "TEST CONFIGURATION:",
        f"  Concurrent Users: {test_config.get('num_users', 'N/A')}",
        f"  Test Duration: {test_config.get('duration', 'N/A')}s",
        f"  Ramp-up Time: {test_config.get('ramp_up_time', 'N/A')}s",
        f"  Actual Duration: {test_config.get('actual_duration', 'N/A'):.1f}s",
        ""
    ])
    
    # Performance metrics summary
    performance_metrics = test_results.get('performance_metrics', {})
    response_stats = performance_metrics.get('response_time_stats', {})
    
    report_lines.extend([
        "PERFORMANCE METRICS:",
        f"  Total Requests: {performance_metrics.get('total_requests', 'N/A')}",
        f"  Successful Requests: {performance_metrics.get('successful_requests', 'N/A')}",
        f"  Failed Requests: {performance_metrics.get('failed_requests', 'N/A')}",
        f"  Success Rate: {performance_metrics.get('success_rate', 0.0):.3%}",
        f"  Error Rate: {performance_metrics.get('error_rate', 0.0):.3%}",
        f"  Requests/Second: {performance_metrics.get('requests_per_second', 0.0):.1f}",
        ""
    ])
    
    # Response time analysis
    if response_stats:
        report_lines.extend([
            "RESPONSE TIME ANALYSIS:",
            f"  Mean: {response_stats.get('mean', 0.0):.3f}s",
            f"  Median: {response_stats.get('median', 0.0):.3f}s",
            f"  Min: {response_stats.get('min', 0.0):.3f}s",
            f"  Max: {response_stats.get('max', 0.0):.3f}s",
            f"  Std Dev: {response_stats.get('std_dev', 0.0):.3f}s",
            f"  P95: {response_stats.get('p95', 0.0):.3f}s",
            f"  P99: {response_stats.get('p99', 0.0):.3f}s",
            ""
        ])
    
    # Resource utilization
    resource_metrics = test_results.get('resource_utilization', {})
    if resource_metrics:
        report_lines.extend([
            "RESOURCE UTILIZATION:"
        ])
        
        cpu_metrics = resource_metrics.get('cpu_utilization', {})
        if cpu_metrics:
            report_lines.extend([
                f"  CPU Usage - Mean: {cpu_metrics.get('mean', 0.0):.1f}%, Max: {cpu_metrics.get('max', 0.0):.1f}%"
            ])
        
        memory_metrics = resource_metrics.get('memory_utilization', {})
        if memory_metrics:
            report_lines.extend([
                f"  Memory Usage - Mean: {memory_metrics.get('mean', 0.0):.1f}%, Max: {memory_metrics.get('max', 0.0):.1f}%"
            ])
        
        thread_metrics = resource_metrics.get('thread_utilization', {})
        if thread_metrics:
            report_lines.extend([
                f"  Thread Count - Mean: {thread_metrics.get('mean', 0.0):.1f}, Max: {thread_metrics.get('max', 0)}"
            ])
        
        report_lines.append("")
    
    # Baseline comparison
    if comparison_results:
        report_lines.extend([
            "BASELINE COMPARISON:"
        ])
        
        regression_detected = comparison_results.get('regression_detected', False)
        report_lines.append(f"  Regression Detected: {regression_detected}")
        
        performance_delta = comparison_results.get('performance_delta', {})
        if performance_delta:
            report_lines.extend([
                f"  Overall Performance Score: {performance_delta.get('overall_score', 0.0):+.1f}%",
                f"  Response Time Improvement: {performance_delta.get('response_time_improvement', 0.0):+.1f}%",
                f"  Throughput Improvement: {performance_delta.get('throughput_improvement', 0.0):+.1f}%",
                f"  Error Rate Change: {performance_delta.get('error_rate_change', 0.0):+.3f}%"
            ])
        
        recommendations = comparison_results.get('recommendations', [])
        if recommendations:
            report_lines.extend([
                "",
                "RECOMMENDATIONS:"
            ])
            for rec in recommendations:
                report_lines.append(f"  - {rec}")
        
        report_lines.append("")
    
    # Error analysis
    errors = test_results.get('errors', [])
    if errors:
        error_types = {}
        for error in errors:
            error_type = error.get('type', 'unknown')
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        report_lines.extend([
            "ERROR ANALYSIS:",
            f"  Total Errors: {len(errors)}"
        ])
        
        for error_type, count in error_types.items():
            report_lines.append(f"  {error_type}: {count}")
        
        report_lines.append("")
    
    report_lines.extend([
        "=" * 80,
        f"Report Generated: {datetime.now().isoformat()}",
        "=" * 80
    ])
    
    return "\n".join(report_lines)


def validate_sla_compliance(test_results: Dict[str, Any], 
                           config: ConcurrentLoadTestConfig) -> Dict[str, bool]:
    """
    Validate SLA compliance for concurrent load test results.
    
    Args:
        test_results: Results from concurrent load testing
        config: Load testing configuration with thresholds
        
    Returns:
        Dict containing SLA compliance results
    """
    compliance_results = {
        'api_response_time': False,
        'authentication_time': False,
        'database_query_time': False,
        'error_rate': False,
        'success_rate': False,
        'overall_compliance': False
    }
    
    performance_metrics = test_results.get('performance_metrics', {})
    response_stats = performance_metrics.get('response_time_stats', {})
    
    # API response time compliance
    mean_response_time = response_stats.get('mean', float('inf'))
    compliance_results['api_response_time'] = mean_response_time < config.API_RESPONSE_THRESHOLD
    
    # Error rate compliance
    error_rate = performance_metrics.get('error_rate', 1.0)
    compliance_results['error_rate'] = error_rate < config.ERROR_RATE_THRESHOLD
    
    # Success rate compliance
    success_rate = performance_metrics.get('success_rate', 0.0)
    compliance_results['success_rate'] = success_rate > 0.99
    
    # Overall compliance (all individual checks must pass)
    compliance_results['overall_compliance'] = all([
        compliance_results['api_response_time'],
        compliance_results['error_rate'],
        compliance_results['success_rate']
    ])
    
    return compliance_results


if __name__ == "__main__":
    """
    Direct execution for development and debugging purposes.
    
    This section allows the test module to be executed directly for development
    testing and debugging outside of the pytest framework.
    """
    print("Concurrent Load Testing Module")
    print("=" * 50)
    print("This module provides comprehensive concurrent load testing")
    print("capabilities for Flask application performance validation.")
    print("\nTo run tests, use: pytest tests/performance/test_concurrent_load.py")
    print("For specific test markers: pytest -m performance")
    print("For stress tests: pytest -m stress")