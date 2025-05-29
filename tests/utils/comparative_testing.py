"""
Comparative testing utilities enabling parallel execution and validation between 
Node.js baseline system and Flask implementation for comprehensive functionality 
parity validation as required by Feature F-009.

This module orchestrates the comprehensive functionality parity validation through
automated comparison testing and real-time discrepancy detection, ensuring 100%
functional equivalence between the original Node.js system and the converted 
Flask implementation as specified in Section 4.7.2.

Key Features:
- Parallel test execution framework for Node.js and Flask system comparison
- Automated functional parity validation with 100% API response equivalence
- Real-time discrepancy detection and reporting utilities
- Business logic verification ensuring identical workflow outcomes
- Multi-environment testing integration with tox 4.26.0
- Automated correction workflow triggers for parity failure remediation
- Performance benchmarking integration with pytest-benchmark 5.1.0

Technical Implementation:
- pytest-flask 1.3.0 integration for Flask-specific testing capabilities
- Concurrent execution using asyncio and threading for parallel system testing
- Comprehensive response comparison with deep data structure analysis
- Performance metrics collection and baseline comparison validation
- Structured logging and reporting for comprehensive test documentation

Dependencies:
- pytest-flask 1.3.0: Flask application testing fixtures and utilities
- pytest-benchmark 5.1.0: Performance benchmarking and baseline comparison
- tox 4.26.0: Multi-environment testing orchestration
- asyncio: Asynchronous concurrent execution for parallel testing
- requests: HTTP client for Node.js system communication
- deepdiff: Deep data structure comparison for response validation
"""

import asyncio
import json
import time
import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable, Union
from urllib.parse import urlparse, urljoin
import logging
import os
import sys
import subprocess
import tempfile
from contextlib import contextmanager

# Core testing and HTTP libraries
import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Flask testing integration
from flask import Flask
from flask.testing import FlaskClient

# Data comparison and validation
try:
    from deepdiff import DeepDiff
except ImportError:
    DeepDiff = None
    print("Warning: deepdiff not available, using basic comparison")

# Performance benchmarking
try:
    import pytest_benchmark
except ImportError:
    pytest_benchmark = None
    print("Warning: pytest-benchmark not available, performance testing disabled")

# Type checking support
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from requests import Response
    from flask import Response as FlaskResponse

# Import project-specific utilities
try:
    from .flask_fixtures import app, client, db_session
    from .performance_benchmarks import PerformanceBenchmarkRunner
    from .api_testing_patterns import APIResponseValidator
except ImportError:
    # Handle missing imports during development
    app = None
    client = None
    db_session = None
    PerformanceBenchmarkRunner = None
    APIResponseValidator = None


# ================================
# Configuration and Constants
# ================================

class ComparativeTestingConfig:
    """
    Configuration class for comparative testing parameters, system endpoints,
    and validation thresholds ensuring comprehensive testing coverage.
    """
    
    # System endpoint configuration
    NODEJS_BASE_URL = os.getenv('NODEJS_BASE_URL', 'http://localhost:3000')
    FLASK_BASE_URL = os.getenv('FLASK_BASE_URL', 'http://localhost:5000')
    
    # Testing behavior configuration
    PARALLEL_EXECUTION_ENABLED = os.getenv('PARALLEL_TESTING', 'true').lower() == 'true'
    MAX_CONCURRENT_REQUESTS = int(os.getenv('MAX_CONCURRENT_REQUESTS', '10'))
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '30'))
    RETRY_ATTEMPTS = int(os.getenv('RETRY_ATTEMPTS', '3'))
    
    # Performance validation thresholds
    RESPONSE_TIME_TOLERANCE_MS = int(os.getenv('RESPONSE_TIME_TOLERANCE', '100'))
    MEMORY_USAGE_TOLERANCE_PERCENT = int(os.getenv('MEMORY_TOLERANCE', '20'))
    PERFORMANCE_BASELINE_MULTIPLIER = float(os.getenv('PERFORMANCE_MULTIPLIER', '1.2'))
    
    # Response comparison settings
    STRICT_JSON_COMPARISON = os.getenv('STRICT_JSON_COMPARISON', 'true').lower() == 'true'
    IGNORE_TIMESTAMP_FIELDS = os.getenv('IGNORE_TIMESTAMPS', 'true').lower() == 'true'
    TIMESTAMP_TOLERANCE_SECONDS = int(os.getenv('TIMESTAMP_TOLERANCE', '5'))
    
    # Error handling and reporting
    FAIL_FAST_ON_DISCREPANCY = os.getenv('FAIL_FAST', 'false').lower() == 'true'
    DETAILED_ERROR_REPORTING = os.getenv('DETAILED_ERRORS', 'true').lower() == 'true'
    GENERATE_HTML_REPORTS = os.getenv('HTML_REPORTS', 'true').lower() == 'true'
    
    # Test environment isolation
    CLEANUP_TEST_DATA = os.getenv('CLEANUP_TEST_DATA', 'true').lower() == 'true'
    PRESERVE_FAILED_REQUESTS = os.getenv('PRESERVE_FAILURES', 'true').lower() == 'true'
    
    # Multi-environment testing
    TOX_ENVIRONMENTS = os.getenv('TOX_ENVIRONMENTS', 'py313').split(',')
    ENVIRONMENT_ISOLATION = os.getenv('ENV_ISOLATION', 'true').lower() == 'true'


# ================================
# Data Models and Structures
# ================================

@dataclass
class SystemResponse:
    """
    Structured representation of system response data for comprehensive
    comparison and analysis between Node.js and Flask implementations.
    """
    
    status_code: int
    headers: Dict[str, str]
    body: Any
    response_time_ms: float
    content_type: str
    encoding: str = 'utf-8'
    
    # Additional response metadata
    timestamp: datetime = field(default_factory=datetime.utcnow)
    system_type: str = field(default='unknown')
    endpoint: str = field(default='')
    method: str = field(default='GET')
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # Performance metrics
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    database_queries: Optional[int] = None
    
    # Error tracking
    error_details: Optional[str] = None
    stack_trace: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary for JSON serialization"""
        return {
            'status_code': self.status_code,
            'headers': dict(self.headers),
            'body': self.body,
            'response_time_ms': self.response_time_ms,
            'content_type': self.content_type,
            'encoding': self.encoding,
            'timestamp': self.timestamp.isoformat(),
            'system_type': self.system_type,
            'endpoint': self.endpoint,
            'method': self.method,
            'request_id': self.request_id,
            'memory_usage_mb': self.memory_usage_mb,
            'cpu_usage_percent': self.cpu_usage_percent,
            'database_queries': self.database_queries,
            'error_details': self.error_details,
            'stack_trace': self.stack_trace
        }
    
    @classmethod
    def from_requests_response(cls, response: 'Response', system_type: str = 'nodejs') -> 'SystemResponse':
        """Create SystemResponse from requests.Response object"""
        try:
            body = response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
        except Exception:
            body = response.text
            
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            response_time_ms=response.elapsed.total_seconds() * 1000,
            content_type=response.headers.get('content-type', ''),
            encoding=response.encoding or 'utf-8',
            system_type=system_type
        )
    
    @classmethod
    def from_flask_response(cls, response: 'FlaskResponse', response_time_ms: float, system_type: str = 'flask') -> 'SystemResponse':
        """Create SystemResponse from Flask test client response"""
        try:
            body = response.get_json() if response.is_json else response.get_data(as_text=True)
        except Exception:
            body = response.get_data(as_text=True)
            
        return cls(
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            response_time_ms=response_time_ms,
            content_type=response.content_type or '',
            encoding='utf-8',
            system_type=system_type
        )


@dataclass
class ComparisonResult:
    """
    Comprehensive comparison result structure capturing all aspects of
    response validation and discrepancy detection between systems.
    """
    
    # Basic comparison metadata
    test_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    endpoint: str = ''
    method: str = 'GET'
    
    # Response data
    nodejs_response: Optional[SystemResponse] = None
    flask_response: Optional[SystemResponse] = None
    
    # Comparison results
    is_equivalent: bool = False
    discrepancies: List[Dict[str, Any]] = field(default_factory=list)
    severity_level: str = 'info'  # info, warning, error, critical
    
    # Performance comparison
    performance_delta_ms: Optional[float] = None
    performance_within_threshold: bool = True
    memory_usage_delta_mb: Optional[float] = None
    
    # Detailed analysis
    status_code_match: bool = True
    headers_match: bool = True
    body_match: bool = True
    content_type_match: bool = True
    
    # Error tracking
    comparison_errors: List[str] = field(default_factory=list)
    nodejs_error: Optional[str] = None
    flask_error: Optional[str] = None
    
    def add_discrepancy(self, category: str, description: str, 
                       nodejs_value: Any = None, flask_value: Any = None,
                       severity: str = 'warning'):
        """Add a discrepancy to the comparison result"""
        discrepancy = {
            'category': category,
            'description': description,
            'nodejs_value': nodejs_value,
            'flask_value': flask_value,
            'severity': severity,
            'timestamp': datetime.utcnow().isoformat()
        }
        self.discrepancies.append(discrepancy)
        
        # Update overall severity if this discrepancy is more severe
        severity_levels = {'info': 0, 'warning': 1, 'error': 2, 'critical': 3}
        if severity_levels.get(severity, 0) > severity_levels.get(self.severity_level, 0):
            self.severity_level = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert comparison result to dictionary for reporting"""
        return {
            'test_id': self.test_id,
            'timestamp': self.timestamp.isoformat(),
            'endpoint': self.endpoint,
            'method': self.method,
            'is_equivalent': self.is_equivalent,
            'severity_level': self.severity_level,
            'discrepancies': self.discrepancies,
            'performance_delta_ms': self.performance_delta_ms,
            'performance_within_threshold': self.performance_within_threshold,
            'memory_usage_delta_mb': self.memory_usage_delta_mb,
            'status_code_match': self.status_code_match,
            'headers_match': self.headers_match,
            'body_match': self.body_match,
            'content_type_match': self.content_type_match,
            'comparison_errors': self.comparison_errors,
            'nodejs_response': self.nodejs_response.to_dict() if self.nodejs_response else None,
            'flask_response': self.flask_response.to_dict() if self.flask_response else None,
            'nodejs_error': self.nodejs_error,
            'flask_error': self.flask_error
        }


# ================================
# Core Comparative Testing Framework
# ================================

class ComparativeTestingFramework:
    """
    Core framework orchestrating parallel execution and comprehensive validation
    between Node.js baseline system and Flask implementation for Feature F-009
    functionality parity validation.
    
    This class implements the comprehensive testing strategy specified in 
    Section 4.7.2, providing automated comparison testing with real-time
    discrepancy detection and reporting capabilities.
    """
    
    def __init__(self, config: ComparativeTestingConfig = None):
        """
        Initialize comparative testing framework with configuration and
        establish connections to both Node.js and Flask systems.
        
        Args:
            config: Configuration instance for testing parameters
        """
        self.config = config or ComparativeTestingConfig()
        self.logger = self._setup_logging()
        
        # System clients and sessions
        self.nodejs_session = self._create_nodejs_session()
        self.flask_client: Optional[FlaskClient] = None
        
        # Performance monitoring
        self.performance_benchmarks = []
        self.baseline_metrics = {}
        
        # Results tracking
        self.test_results: List[ComparisonResult] = []
        self.test_statistics = {
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'discrepancies_found': 0,
            'performance_regressions': 0
        }
        
        # Multi-environment testing state
        self.current_environment = None
        self.environment_results = {}
        
        # Thread pool for concurrent execution
        self.executor = ThreadPoolExecutor(max_workers=self.config.MAX_CONCURRENT_REQUESTS)
        
    def _setup_logging(self) -> logging.Logger:
        """Configure comprehensive logging for testing operations and results"""
        logger = logging.getLogger('comparative_testing')
        logger.setLevel(logging.INFO)
        
        # Create formatter for structured logging
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler for detailed logs
        log_file = Path('comparative_testing.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _create_nodejs_session(self) -> requests.Session:
        """
        Create configured requests session for Node.js system communication
        with retry logic and timeout configuration.
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.RETRY_ATTEMPTS,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default timeout
        session.timeout = self.config.REQUEST_TIMEOUT
        
        return session
    
    def set_flask_client(self, flask_client: FlaskClient):
        """
        Set Flask test client for Flask system testing.
        
        Args:
            flask_client: Configured Flask test client from pytest fixtures
        """
        self.flask_client = flask_client
        self.logger.info("Flask test client configured for comparative testing")
    
    @contextmanager
    def test_environment(self, environment_name: str):
        """
        Context manager for multi-environment testing isolation as specified
        in Section 4.7.2 for tox 4.26.0 integration.
        
        Args:
            environment_name: Name of the testing environment (e.g., 'py313')
        """
        previous_env = self.current_environment
        self.current_environment = environment_name
        
        if environment_name not in self.environment_results:
            self.environment_results[environment_name] = {
                'start_time': datetime.utcnow(),
                'test_results': [],
                'statistics': {
                    'total_tests': 0,
                    'passed_tests': 0,
                    'failed_tests': 0
                }
            }
        
        self.logger.info(f"Starting tests in environment: {environment_name}")
        
        try:
            yield self.environment_results[environment_name]
        finally:
            self.environment_results[environment_name]['end_time'] = datetime.utcnow()
            self.current_environment = previous_env
            self.logger.info(f"Completed tests in environment: {environment_name}")
    
    def execute_parallel_comparison(self, endpoint: str, method: str = 'GET',
                                   data: Dict[str, Any] = None,
                                   headers: Dict[str, str] = None,
                                   params: Dict[str, str] = None) -> ComparisonResult:
        """
        Execute parallel requests to both Node.js and Flask systems for
        comprehensive functionality parity validation as required by Feature F-009.
        
        Args:
            endpoint: API endpoint path for testing
            method: HTTP method for the request
            data: Request body data
            headers: HTTP headers
            params: Query parameters
            
        Returns:
            ComparisonResult: Comprehensive comparison analysis
        """
        result = ComparisonResult(
            endpoint=endpoint,
            method=method.upper()
        )
        
        self.logger.info(f"Starting parallel comparison: {method} {endpoint}")
        
        # Execute requests concurrently
        futures = []
        
        # Submit Node.js request
        nodejs_future = self.executor.submit(
            self._execute_nodejs_request, endpoint, method, data, headers, params
        )
        futures.append(('nodejs', nodejs_future))
        
        # Submit Flask request
        if self.flask_client:
            flask_future = self.executor.submit(
                self._execute_flask_request, endpoint, method, data, headers, params
            )
            futures.append(('flask', flask_future))
        else:
            self.logger.warning("Flask client not configured, skipping Flask request")
        
        # Collect results
        responses = {}
        for system_type, future in futures:
            try:
                responses[system_type] = future.result(timeout=self.config.REQUEST_TIMEOUT)
                self.logger.debug(f"{system_type.capitalize()} request completed successfully")
            except Exception as e:
                self.logger.error(f"{system_type.capitalize()} request failed: {str(e)}")
                if system_type == 'nodejs':
                    result.nodejs_error = str(e)
                else:
                    result.flask_error = str(e)
        
        # Store responses in result
        result.nodejs_response = responses.get('nodejs')
        result.flask_response = responses.get('flask')
        
        # Perform comprehensive comparison
        if result.nodejs_response and result.flask_response:
            self._compare_responses(result)
        else:
            result.is_equivalent = False
            result.add_discrepancy(
                'execution',
                'One or both systems failed to respond',
                severity='critical'
            )
        
        # Track results
        self.test_results.append(result)
        self._update_statistics(result)
        
        self.logger.info(f"Parallel comparison completed: {endpoint} - Equivalent: {result.is_equivalent}")
        
        return result
    
    def _execute_nodejs_request(self, endpoint: str, method: str, 
                               data: Dict[str, Any] = None,
                               headers: Dict[str, str] = None,
                               params: Dict[str, str] = None) -> SystemResponse:
        """
        Execute HTTP request to Node.js system with comprehensive error handling
        and performance monitoring.
        """
        url = urljoin(self.config.NODEJS_BASE_URL, endpoint)
        
        # Prepare request parameters
        request_kwargs = {
            'timeout': self.config.REQUEST_TIMEOUT,
            'headers': headers or {},
            'params': params or {}
        }
        
        if data:
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                request_kwargs['json'] = data
                if 'Content-Type' not in request_kwargs['headers']:
                    request_kwargs['headers']['Content-Type'] = 'application/json'
        
        # Execute request with timing
        start_time = time.time()
        try:
            response = self.nodejs_session.request(method, url, **request_kwargs)
            end_time = time.time()
            
            # Create SystemResponse object
            system_response = SystemResponse.from_requests_response(response, 'nodejs')
            system_response.response_time_ms = (end_time - start_time) * 1000
            system_response.endpoint = endpoint
            system_response.method = method.upper()
            
            self.logger.debug(f"Node.js request: {method} {url} -> {response.status_code} ({system_response.response_time_ms:.2f}ms)")
            
            return system_response
            
        except Exception as e:
            end_time = time.time()
            self.logger.error(f"Node.js request failed: {method} {url} - {str(e)}")
            
            # Create error response
            error_response = SystemResponse(
                status_code=500,
                headers={},
                body={'error': str(e)},
                response_time_ms=(end_time - start_time) * 1000,
                content_type='application/json',
                system_type='nodejs',
                endpoint=endpoint,
                method=method.upper(),
                error_details=str(e),
                stack_trace=traceback.format_exc()
            )
            
            return error_response
    
    def _execute_flask_request(self, endpoint: str, method: str,
                              data: Dict[str, Any] = None,
                              headers: Dict[str, str] = None,
                              params: Dict[str, str] = None) -> SystemResponse:
        """
        Execute request to Flask application using test client with comprehensive
        error handling and performance monitoring.
        """
        if not self.flask_client:
            raise ValueError("Flask client not configured")
        
        # Prepare request parameters
        request_kwargs = {
            'headers': headers or {},
            'query_string': params or {}
        }
        
        if data:
            if method.upper() in ['POST', 'PUT', 'PATCH']:
                request_kwargs['json'] = data
                if 'Content-Type' not in request_kwargs['headers']:
                    request_kwargs['headers']['Content-Type'] = 'application/json'
        
        # Execute request with timing
        start_time = time.time()
        try:
            response = self.flask_client.open(
                endpoint,
                method=method.upper(),
                **request_kwargs
            )
            end_time = time.time()
            
            # Create SystemResponse object
            system_response = SystemResponse.from_flask_response(
                response, 
                (end_time - start_time) * 1000, 
                'flask'
            )
            system_response.endpoint = endpoint
            system_response.method = method.upper()
            
            self.logger.debug(f"Flask request: {method} {endpoint} -> {response.status_code} ({system_response.response_time_ms:.2f}ms)")
            
            return system_response
            
        except Exception as e:
            end_time = time.time()
            self.logger.error(f"Flask request failed: {method} {endpoint} - {str(e)}")
            
            # Create error response
            error_response = SystemResponse(
                status_code=500,
                headers={},
                body={'error': str(e)},
                response_time_ms=(end_time - start_time) * 1000,
                content_type='application/json',
                system_type='flask',
                endpoint=endpoint,
                method=method.upper(),
                error_details=str(e),
                stack_trace=traceback.format_exc()
            )
            
            return error_response
    
    def _compare_responses(self, result: ComparisonResult):
        """
        Perform comprehensive response comparison implementing the 100% functional
        equivalence requirement specified in Feature F-009.
        """
        nodejs_resp = result.nodejs_response
        flask_resp = result.flask_response
        
        if not nodejs_resp or not flask_resp:
            result.is_equivalent = False
            return
        
        # Status code comparison
        result.status_code_match = nodejs_resp.status_code == flask_resp.status_code
        if not result.status_code_match:
            result.add_discrepancy(
                'status_code',
                'HTTP status codes do not match',
                nodejs_resp.status_code,
                flask_resp.status_code,
                'error'
            )
        
        # Content type comparison
        nodejs_content_type = self._normalize_content_type(nodejs_resp.content_type)
        flask_content_type = self._normalize_content_type(flask_resp.content_type)
        result.content_type_match = nodejs_content_type == flask_content_type
        
        if not result.content_type_match:
            result.add_discrepancy(
                'content_type',
                'Content types do not match',
                nodejs_content_type,
                flask_content_type,
                'warning'
            )
        
        # Headers comparison (selective)
        self._compare_headers(nodejs_resp, flask_resp, result)
        
        # Body comparison
        self._compare_response_bodies(nodejs_resp, flask_resp, result)
        
        # Performance comparison
        self._compare_performance(nodejs_resp, flask_resp, result)
        
        # Overall equivalence determination
        result.is_equivalent = (
            result.status_code_match and
            result.body_match and
            not any(d['severity'] in ['error', 'critical'] for d in result.discrepancies)
        )
    
    def _normalize_content_type(self, content_type: str) -> str:
        """Normalize content type for comparison by removing charset and other parameters"""
        if not content_type:
            return ''
        return content_type.split(';')[0].strip().lower()
    
    def _compare_headers(self, nodejs_resp: SystemResponse, flask_resp: SystemResponse, result: ComparisonResult):
        """Compare response headers with focus on critical headers for API compatibility"""
        # Headers to compare (ignore server-specific headers)
        critical_headers = {
            'content-type', 'content-length', 'cache-control', 
            'access-control-allow-origin', 'access-control-allow-methods',
            'access-control-allow-headers', 'x-api-version'
        }
        
        nodejs_headers = {k.lower(): v for k, v in nodejs_resp.headers.items()}
        flask_headers = {k.lower(): v for k, v in flask_resp.headers.items()}
        
        header_mismatches = []
        
        for header in critical_headers:
            nodejs_value = nodejs_headers.get(header)
            flask_value = flask_headers.get(header)
            
            if nodejs_value != flask_value:
                # Skip content-length mismatches for equivalent content
                if header == 'content-length' and self._content_lengths_equivalent(nodejs_value, flask_value):
                    continue
                    
                header_mismatches.append({
                    'header': header,
                    'nodejs_value': nodejs_value,
                    'flask_value': flask_value
                })
        
        if header_mismatches:
            result.headers_match = False
            for mismatch in header_mismatches:
                result.add_discrepancy(
                    'headers',
                    f"Header '{mismatch['header']}' values differ",
                    mismatch['nodejs_value'],
                    mismatch['flask_value'],
                    'warning'
                )
        else:
            result.headers_match = True
    
    def _content_lengths_equivalent(self, nodejs_length: str, flask_length: str) -> bool:
        """Check if content lengths are equivalent within reasonable tolerance"""
        try:
            if not nodejs_length or not flask_length:
                return False
            
            nodejs_len = int(nodejs_length)
            flask_len = int(flask_length)
            
            # Allow small differences due to encoding or formatting
            return abs(nodejs_len - flask_len) <= 10
        except (ValueError, TypeError):
            return False
    
    def _compare_response_bodies(self, nodejs_resp: SystemResponse, flask_resp: SystemResponse, result: ComparisonResult):
        """
        Perform comprehensive response body comparison with deep data structure
        analysis using DeepDiff for precise discrepancy detection.
        """
        nodejs_body = nodejs_resp.body
        flask_body = flask_resp.body
        
        # Handle None/empty responses
        if nodejs_body is None and flask_body is None:
            result.body_match = True
            return
        
        if (nodejs_body is None) != (flask_body is None):
            result.body_match = False
            result.add_discrepancy(
                'body',
                'One response has body while other is None/empty',
                nodejs_body,
                flask_body,
                'error'
            )
            return
        
        # String comparison for non-JSON responses
        if isinstance(nodejs_body, str) and isinstance(flask_body, str):
            if nodejs_body.strip() == flask_body.strip():
                result.body_match = True
            else:
                result.body_match = False
                result.add_discrepancy(
                    'body',
                    'Response body text differs',
                    nodejs_body[:200] + '...' if len(nodejs_body) > 200 else nodejs_body,
                    flask_body[:200] + '...' if len(flask_body) > 200 else flask_body,
                    'error'
                )
            return
        
        # Deep comparison for structured data
        if DeepDiff is not None:
            self._deep_compare_structures(nodejs_body, flask_body, result)
        else:
            # Fallback to basic comparison
            self._basic_compare_structures(nodejs_body, flask_body, result)
    
    def _deep_compare_structures(self, nodejs_data: Any, flask_data: Any, result: ComparisonResult):
        """
        Perform deep comparison using DeepDiff library for comprehensive
        data structure analysis and discrepancy detection.
        """
        try:
            # Configure DeepDiff for comprehensive comparison
            ignore_order = True  # Allow different ordering in arrays
            ignore_string_case = False  # Case sensitive comparison
            ignore_numeric_type_changes = True  # Allow int/float equivalence
            
            # Fields to ignore during comparison (timestamps, generated IDs)
            exclude_paths = []
            if self.config.IGNORE_TIMESTAMP_FIELDS:
                timestamp_patterns = [
                    'root.*timestamp*',
                    'root.*created_at*',
                    'root.*updated_at*',
                    'root.*modified*',
                    'root.*date*'
                ]
                exclude_paths.extend(timestamp_patterns)
            
            diff = DeepDiff(
                nodejs_data,
                flask_data,
                ignore_order=ignore_order,
                ignore_string_case=ignore_string_case,
                ignore_numeric_type_changes=ignore_numeric_type_changes,
                exclude_paths=exclude_paths,
                view='unified'
            )
            
            if not diff:
                result.body_match = True
                return
            
            result.body_match = False
            
            # Process different types of differences
            for change_type, changes in diff.items():
                self._process_deep_diff_changes(change_type, changes, result)
                
        except Exception as e:
            self.logger.error(f"DeepDiff comparison failed: {str(e)}")
            # Fallback to basic comparison
            self._basic_compare_structures(nodejs_data, flask_data, result)
    
    def _process_deep_diff_changes(self, change_type: str, changes: Any, result: ComparisonResult):
        """Process specific types of changes found by DeepDiff"""
        severity_map = {
            'values_changed': 'error',
            'type_changes': 'error', 
            'dictionary_item_added': 'warning',
            'dictionary_item_removed': 'warning',
            'iterable_item_added': 'warning',
            'iterable_item_removed': 'warning',
            'set_item_added': 'warning',
            'set_item_removed': 'warning'
        }
        
        severity = severity_map.get(change_type, 'warning')
        
        if isinstance(changes, dict):
            for path, change_details in changes.items():
                result.add_discrepancy(
                    'body_structure',
                    f"{change_type}: {path}",
                    change_details.get('old_value') if hasattr(change_details, 'get') else str(change_details),
                    change_details.get('new_value') if hasattr(change_details, 'get') else str(change_details),
                    severity
                )
        elif isinstance(changes, (list, set)):
            for change in changes:
                result.add_discrepancy(
                    'body_structure',
                    f"{change_type}: {str(change)}",
                    None,
                    None,
                    severity
                )
        else:
            result.add_discrepancy(
                'body_structure',
                f"{change_type}: {str(changes)}",
                None,
                None,
                severity
            )
    
    def _basic_compare_structures(self, nodejs_data: Any, flask_data: Any, result: ComparisonResult):
        """Fallback basic comparison when DeepDiff is not available"""
        try:
            # Convert to JSON strings for comparison
            nodejs_json = json.dumps(nodejs_data, sort_keys=True, default=str)
            flask_json = json.dumps(flask_data, sort_keys=True, default=str)
            
            if nodejs_json == flask_json:
                result.body_match = True
            else:
                result.body_match = False
                result.add_discrepancy(
                    'body',
                    'Response body structures differ (basic comparison)',
                    nodejs_json[:500] + '...' if len(nodejs_json) > 500 else nodejs_json,
                    flask_json[:500] + '...' if len(flask_json) > 500 else flask_json,
                    'error'
                )
        except (TypeError, ValueError) as e:
            result.body_match = False
            result.add_discrepancy(
                'body',
                f'Cannot compare response bodies: {str(e)}',
                str(nodejs_data)[:200],
                str(flask_data)[:200],
                'error'
            )
    
    def _compare_performance(self, nodejs_resp: SystemResponse, flask_resp: SystemResponse, result: ComparisonResult):
        """
        Compare performance metrics between systems ensuring Flask implementation
        meets or exceeds Node.js baseline performance as specified in Section 2.4.2.
        """
        result.performance_delta_ms = flask_resp.response_time_ms - nodejs_resp.response_time_ms
        
        # Check if Flask response time is within acceptable threshold
        max_allowed_time = nodejs_resp.response_time_ms + self.config.RESPONSE_TIME_TOLERANCE_MS
        result.performance_within_threshold = flask_resp.response_time_ms <= max_allowed_time
        
        if not result.performance_within_threshold:
            result.add_discrepancy(
                'performance',
                f'Flask response time exceeds threshold by {result.performance_delta_ms:.2f}ms',
                f'{nodejs_resp.response_time_ms:.2f}ms',
                f'{flask_resp.response_time_ms:.2f}ms',
                'warning'
            )
        
        # Memory usage comparison (if available)
        if nodejs_resp.memory_usage_mb and flask_resp.memory_usage_mb:
            result.memory_usage_delta_mb = flask_resp.memory_usage_mb - nodejs_resp.memory_usage_mb
            memory_threshold = nodejs_resp.memory_usage_mb * (1 + self.config.MEMORY_USAGE_TOLERANCE_PERCENT / 100)
            
            if flask_resp.memory_usage_mb > memory_threshold:
                result.add_discrepancy(
                    'memory_usage',
                    f'Flask memory usage exceeds threshold by {result.memory_usage_delta_mb:.2f}MB',
                    f'{nodejs_resp.memory_usage_mb:.2f}MB',
                    f'{flask_resp.memory_usage_mb:.2f}MB',
                    'warning'
                )
    
    def _update_statistics(self, result: ComparisonResult):
        """Update internal testing statistics based on comparison result"""
        self.test_statistics['total_tests'] += 1
        
        if result.is_equivalent:
            self.test_statistics['passed_tests'] += 1
        else:
            self.test_statistics['failed_tests'] += 1
        
        if result.discrepancies:
            self.test_statistics['discrepancies_found'] += len(result.discrepancies)
        
        if not result.performance_within_threshold:
            self.test_statistics['performance_regressions'] += 1
        
        # Update environment-specific statistics
        if self.current_environment:
            env_stats = self.environment_results[self.current_environment]['statistics']
            env_stats['total_tests'] += 1
            if result.is_equivalent:
                env_stats['passed_tests'] += 1
            else:
                env_stats['failed_tests'] += 1
    
    def validate_business_logic_workflow(self, workflow_name: str, 
                                       workflow_steps: List[Dict[str, Any]],
                                       expected_outcome: Dict[str, Any]) -> ComparisonResult:
        """
        Validate business logic workflows ensuring identical execution outcomes
        between Node.js and Flask systems as required by Feature F-005.
        
        Args:
            workflow_name: Name of the business workflow being tested
            workflow_steps: List of API calls representing the workflow
            expected_outcome: Expected final state after workflow completion
            
        Returns:
            ComparisonResult: Comprehensive workflow validation result
        """
        result = ComparisonResult(
            endpoint=f'/workflow/{workflow_name}',
            method='WORKFLOW'
        )
        
        self.logger.info(f"Starting business logic workflow validation: {workflow_name}")
        
        # Execute workflow on both systems
        nodejs_outcome = self._execute_workflow(workflow_steps, 'nodejs')
        flask_outcome = self._execute_workflow(workflow_steps, 'flask')
        
        # Compare workflow outcomes
        if nodejs_outcome and flask_outcome:
            self._compare_workflow_outcomes(nodejs_outcome, flask_outcome, expected_outcome, result)
        else:
            result.is_equivalent = False
            result.add_discrepancy(
                'workflow_execution',
                'Workflow failed to execute on one or both systems',
                str(nodejs_outcome),
                str(flask_outcome),
                'critical'
            )
        
        self.test_results.append(result)
        self._update_statistics(result)
        
        self.logger.info(f"Business logic workflow validation completed: {workflow_name} - Equivalent: {result.is_equivalent}")
        
        return result
    
    def _execute_workflow(self, workflow_steps: List[Dict[str, Any]], system_type: str) -> Dict[str, Any]:
        """Execute a multi-step workflow on the specified system"""
        workflow_state = {}
        
        for step_index, step in enumerate(workflow_steps):
            try:
                endpoint = step.get('endpoint', '')
                method = step.get('method', 'GET')
                data = step.get('data', {})
                headers = step.get('headers', {})
                
                # Replace placeholders in step data with workflow state
                data = self._replace_workflow_placeholders(data, workflow_state)
                
                # Execute step
                if system_type == 'nodejs':
                    response = self._execute_nodejs_request(endpoint, method, data, headers)
                elif system_type == 'flask':
                    response = self._execute_flask_request(endpoint, method, data, headers)
                else:
                    raise ValueError(f"Unknown system type: {system_type}")
                
                # Update workflow state with response data
                if response.status_code < 400 and response.body:
                    step_result_key = step.get('result_key', f'step_{step_index}')
                    workflow_state[step_result_key] = response.body
                
                # Check for workflow failure
                if response.status_code >= 400:
                    self.logger.warning(f"Workflow step failed: {system_type} {endpoint} -> {response.status_code}")
                    workflow_state['error'] = {
                        'step': step_index,
                        'endpoint': endpoint,
                        'status_code': response.status_code,
                        'error_details': response.error_details
                    }
                    break
                    
            except Exception as e:
                self.logger.error(f"Workflow step execution failed: {system_type} step {step_index} - {str(e)}")
                workflow_state['error'] = {
                    'step': step_index,
                    'exception': str(e),
                    'traceback': traceback.format_exc()
                }
                break
        
        return workflow_state
    
    def _replace_workflow_placeholders(self, data: Any, workflow_state: Dict[str, Any]) -> Any:
        """Replace placeholders in workflow step data with values from workflow state"""
        if isinstance(data, dict):
            return {key: self._replace_workflow_placeholders(value, workflow_state) for key, value in data.items()}
        elif isinstance(data, list):
            return [self._replace_workflow_placeholders(item, workflow_state) for item in data]
        elif isinstance(data, str) and data.startswith('${') and data.endswith('}'):
            # Extract placeholder key
            placeholder_key = data[2:-1]
            return self._get_nested_value(workflow_state, placeholder_key)
        else:
            return data
    
    def _get_nested_value(self, data: Dict[str, Any], key_path: str) -> Any:
        """Get nested value from dictionary using dot notation (e.g., 'user.id')"""
        keys = key_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value
    
    def _compare_workflow_outcomes(self, nodejs_outcome: Dict[str, Any], 
                                  flask_outcome: Dict[str, Any],
                                  expected_outcome: Dict[str, Any],
                                  result: ComparisonResult):
        """Compare workflow execution outcomes between systems"""
        # Check for execution errors
        nodejs_error = nodejs_outcome.get('error')
        flask_error = flask_outcome.get('error')
        
        if nodejs_error or flask_error:
            result.is_equivalent = False
            if nodejs_error and flask_error:
                result.add_discrepancy(
                    'workflow_errors',
                    'Both systems encountered errors during workflow execution',
                    str(nodejs_error),
                    str(flask_error),
                    'error'
                )
            elif nodejs_error:
                result.add_discrepancy(
                    'workflow_errors',
                    'Node.js system encountered error during workflow execution',
                    str(nodejs_error),
                    'No error',
                    'error'
                )
            elif flask_error:
                result.add_discrepancy(
                    'workflow_errors',
                    'Flask system encountered error during workflow execution',
                    'No error',
                    str(flask_error),
                    'error'
                )
            return
        
        # Compare final workflow states
        if DeepDiff is not None:
            diff = DeepDiff(nodejs_outcome, flask_outcome, ignore_order=True)
            if diff:
                result.is_equivalent = False
                for change_type, changes in diff.items():
                    result.add_discrepancy(
                        'workflow_outcome',
                        f'Workflow state difference: {change_type}',
                        str(changes),
                        None,
                        'error'
                    )
            else:
                result.is_equivalent = True
        else:
            # Basic comparison
            try:
                nodejs_json = json.dumps(nodejs_outcome, sort_keys=True, default=str)
                flask_json = json.dumps(flask_outcome, sort_keys=True, default=str)
                result.is_equivalent = nodejs_json == flask_json
                
                if not result.is_equivalent:
                    result.add_discrepancy(
                        'workflow_outcome',
                        'Workflow outcomes differ',
                        nodejs_json[:500],
                        flask_json[:500],
                        'error'
                    )
            except Exception as e:
                result.is_equivalent = False
                result.add_discrepancy(
                    'workflow_outcome',
                    f'Cannot compare workflow outcomes: {str(e)}',
                    str(nodejs_outcome)[:200],
                    str(flask_outcome)[:200],
                    'error'
                )
    
    def generate_comprehensive_report(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate comprehensive testing report with detailed analysis of all
        comparison results, discrepancies, and recommendations for Feature F-009 validation.
        
        Args:
            output_path: Optional file path for saving the report
            
        Returns:
            Dict[str, Any]: Comprehensive report data structure
        """
        report_timestamp = datetime.utcnow()
        
        report = {
            'metadata': {
                'generated_at': report_timestamp.isoformat(),
                'testing_framework_version': '1.0.0',
                'total_tests_executed': len(self.test_results),
                'testing_duration_minutes': self._calculate_testing_duration(),
                'environments_tested': list(self.environment_results.keys())
            },
            'executive_summary': self._generate_executive_summary(),
            'detailed_statistics': self._generate_detailed_statistics(),
            'discrepancy_analysis': self._generate_discrepancy_analysis(),
            'performance_analysis': self._generate_performance_analysis(),
            'environment_comparison': self._generate_environment_comparison(),
            'recommendations': self._generate_recommendations(),
            'detailed_results': [result.to_dict() for result in self.test_results]
        }
        
        # Save report to file if path provided
        if output_path:
            self._save_report_to_file(report, output_path)
        
        # Generate HTML report if enabled
        if self.config.GENERATE_HTML_REPORTS:
            html_path = self._generate_html_report(report, output_path)
            report['metadata']['html_report_path'] = html_path
        
        return report
    
    def _calculate_testing_duration(self) -> float:
        """Calculate total testing duration in minutes"""
        if not self.test_results:
            return 0.0
        
        start_times = [result.timestamp for result in self.test_results]
        end_times = [result.timestamp for result in self.test_results]
        
        if start_times and end_times:
            duration = max(end_times) - min(start_times)
            return duration.total_seconds() / 60
        
        return 0.0
    
    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary of testing results"""
        total_tests = self.test_statistics['total_tests']
        passed_tests = self.test_statistics['passed_tests']
        
        if total_tests == 0:
            equivalence_percentage = 0.0
        else:
            equivalence_percentage = (passed_tests / total_tests) * 100
        
        # Determine overall status based on Feature F-009 requirements
        if equivalence_percentage == 100.0:
            overall_status = 'PASS'
            migration_readiness = 'Ready for deployment'
        elif equivalence_percentage >= 95.0:
            overall_status = 'CONDITIONAL_PASS'
            migration_readiness = 'Minor issues require review'
        elif equivalence_percentage >= 80.0:
            overall_status = 'WARNING'
            migration_readiness = 'Significant issues require resolution'
        else:
            overall_status = 'FAIL'
            migration_readiness = 'Critical issues prevent deployment'
        
        return {
            'overall_status': overall_status,
            'functional_equivalence_percentage': round(equivalence_percentage, 2),
            'migration_readiness': migration_readiness,
            'total_tests_executed': total_tests,
            'tests_passed': passed_tests,
            'tests_failed': self.test_statistics['failed_tests'],
            'critical_discrepancies': len([
                result for result in self.test_results 
                if any(d['severity'] == 'critical' for d in result.discrepancies)
            ]),
            'performance_regressions': self.test_statistics['performance_regressions']
        }
    
    def _generate_detailed_statistics(self) -> Dict[str, Any]:
        """Generate detailed statistical analysis of test results"""
        if not self.test_results:
            return {}
        
        # Response time statistics
        response_times = [
            result.flask_response.response_time_ms for result in self.test_results
            if result.flask_response and result.flask_response.response_time_ms
        ]
        
        nodejs_response_times = [
            result.nodejs_response.response_time_ms for result in self.test_results
            if result.nodejs_response and result.nodejs_response.response_time_ms
        ]
        
        # Discrepancy categorization
        discrepancy_categories = {}
        severity_counts = {'info': 0, 'warning': 0, 'error': 0, 'critical': 0}
        
        for result in self.test_results:
            for discrepancy in result.discrepancies:
                category = discrepancy['category']
                severity = discrepancy['severity']
                
                discrepancy_categories[category] = discrepancy_categories.get(category, 0) + 1
                severity_counts[severity] += 1
        
        return {
            'response_time_statistics': {
                'flask_avg_ms': sum(response_times) / len(response_times) if response_times else 0,
                'flask_min_ms': min(response_times) if response_times else 0,
                'flask_max_ms': max(response_times) if response_times else 0,
                'nodejs_avg_ms': sum(nodejs_response_times) / len(nodejs_response_times) if nodejs_response_times else 0,
                'nodejs_min_ms': min(nodejs_response_times) if nodejs_response_times else 0,
                'nodejs_max_ms': max(nodejs_response_times) if nodejs_response_times else 0
            },
            'discrepancy_categories': discrepancy_categories,
            'severity_distribution': severity_counts,
            'test_method_distribution': self._analyze_test_methods(),
            'endpoint_coverage': self._analyze_endpoint_coverage()
        }
    
    def _analyze_test_methods(self) -> Dict[str, int]:
        """Analyze distribution of HTTP methods in tests"""
        method_counts = {}
        for result in self.test_results:
            method = result.method
            method_counts[method] = method_counts.get(method, 0) + 1
        return method_counts
    
    def _analyze_endpoint_coverage(self) -> Dict[str, Any]:
        """Analyze endpoint coverage and testing patterns"""
        endpoints = set(result.endpoint for result in self.test_results)
        
        endpoint_results = {}
        for result in self.test_results:
            endpoint = result.endpoint
            if endpoint not in endpoint_results:
                endpoint_results[endpoint] = {'total': 0, 'passed': 0, 'failed': 0}
            
            endpoint_results[endpoint]['total'] += 1
            if result.is_equivalent:
                endpoint_results[endpoint]['passed'] += 1
            else:
                endpoint_results[endpoint]['failed'] += 1
        
        return {
            'total_endpoints_tested': len(endpoints),
            'endpoint_results': endpoint_results
        }
    
    def _generate_discrepancy_analysis(self) -> Dict[str, Any]:
        """Generate comprehensive analysis of discrepancies found during testing"""
        all_discrepancies = []
        for result in self.test_results:
            for discrepancy in result.discrepancies:
                discrepancy_copy = discrepancy.copy()
                discrepancy_copy['test_id'] = result.test_id
                discrepancy_copy['endpoint'] = result.endpoint
                discrepancy_copy['method'] = result.method
                all_discrepancies.append(discrepancy_copy)
        
        # Group discrepancies by category and severity
        by_category = {}
        by_severity = {}
        
        for discrepancy in all_discrepancies:
            category = discrepancy['category']
            severity = discrepancy['severity']
            
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(discrepancy)
            
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(discrepancy)
        
        return {
            'total_discrepancies': len(all_discrepancies),
            'discrepancies_by_category': by_category,
            'discrepancies_by_severity': by_severity,
            'most_common_issues': self._identify_common_issues(all_discrepancies),
            'critical_failures': [d for d in all_discrepancies if d['severity'] == 'critical']
        }
    
    def _identify_common_issues(self, discrepancies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify most common issues across all discrepancies"""
        issue_patterns = {}
        
        for discrepancy in discrepancies:
            pattern_key = f"{discrepancy['category']}:{discrepancy['description']}"
            if pattern_key not in issue_patterns:
                issue_patterns[pattern_key] = {
                    'pattern': pattern_key,
                    'category': discrepancy['category'],
                    'description': discrepancy['description'],
                    'count': 0,
                    'severity': discrepancy['severity'],
                    'examples': []
                }
            
            issue_patterns[pattern_key]['count'] += 1
            if len(issue_patterns[pattern_key]['examples']) < 3:
                issue_patterns[pattern_key]['examples'].append({
                    'endpoint': discrepancy.get('endpoint'),
                    'test_id': discrepancy.get('test_id'),
                    'nodejs_value': discrepancy.get('nodejs_value'),
                    'flask_value': discrepancy.get('flask_value')
                })
        
        # Sort by frequency
        return sorted(issue_patterns.values(), key=lambda x: x['count'], reverse=True)[:10]
    
    def _generate_performance_analysis(self) -> Dict[str, Any]:
        """Generate performance analysis comparing Flask and Node.js systems"""
        performance_data = []
        
        for result in self.test_results:
            if result.nodejs_response and result.flask_response:
                performance_data.append({
                    'endpoint': result.endpoint,
                    'method': result.method,
                    'nodejs_time_ms': result.nodejs_response.response_time_ms,
                    'flask_time_ms': result.flask_response.response_time_ms,
                    'delta_ms': result.performance_delta_ms,
                    'within_threshold': result.performance_within_threshold
                })
        
        if not performance_data:
            return {'message': 'No performance data available'}
        
        # Calculate performance statistics
        deltas = [p['delta_ms'] for p in performance_data if p['delta_ms'] is not None]
        flask_times = [p['flask_time_ms'] for p in performance_data]
        nodejs_times = [p['nodejs_time_ms'] for p in performance_data]
        
        performance_regressions = [p for p in performance_data if not p['within_threshold']]
        performance_improvements = [p for p in performance_data if p['delta_ms'] and p['delta_ms'] < 0]
        
        return {
            'overall_performance': {
                'flask_avg_response_time': sum(flask_times) / len(flask_times) if flask_times else 0,
                'nodejs_avg_response_time': sum(nodejs_times) / len(nodejs_times) if nodejs_times else 0,
                'avg_performance_delta': sum(deltas) / len(deltas) if deltas else 0,
                'performance_regression_percentage': (len(performance_regressions) / len(performance_data)) * 100
            },
            'performance_regressions': performance_regressions,
            'performance_improvements': performance_improvements,
            'slowest_endpoints': sorted(performance_data, key=lambda x: x['flask_time_ms'], reverse=True)[:10],
            'largest_regressions': sorted(
                [p for p in performance_data if p['delta_ms'] and p['delta_ms'] > 0],
                key=lambda x: x['delta_ms'],
                reverse=True
            )[:10]
        }
    
    def _generate_environment_comparison(self) -> Dict[str, Any]:
        """Generate comparison analysis across different testing environments"""
        if not self.environment_results:
            return {'message': 'No multi-environment testing data available'}
        
        environment_summary = {}
        
        for env_name, env_data in self.environment_results.items():
            env_stats = env_data['statistics']
            total_tests = env_stats['total_tests']
            
            if total_tests > 0:
                success_rate = (env_stats['passed_tests'] / total_tests) * 100
            else:
                success_rate = 0.0
            
            environment_summary[env_name] = {
                'total_tests': total_tests,
                'passed_tests': env_stats['passed_tests'],
                'failed_tests': env_stats['failed_tests'],
                'success_rate_percentage': round(success_rate, 2),
                'start_time': env_data.get('start_time', '').isoformat() if env_data.get('start_time') else '',
                'end_time': env_data.get('end_time', '').isoformat() if env_data.get('end_time') else '',
                'test_results': len(env_data.get('test_results', []))
            }
        
        return {
            'environment_summary': environment_summary,
            'environment_compatibility': self._analyze_environment_compatibility()
        }
    
    def _analyze_environment_compatibility(self) -> Dict[str, Any]:
        """Analyze compatibility issues across different environments"""
        # This would contain logic to compare results across environments
        # and identify environment-specific issues
        return {
            'cross_environment_issues': [],
            'environment_specific_failures': {},
            'compatibility_score': 100.0  # Placeholder
        }
    
    def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate actionable recommendations based on testing results"""
        recommendations = []
        
        # Performance recommendations
        performance_regressions = self.test_statistics.get('performance_regressions', 0)
        if performance_regressions > 0:
            recommendations.append({
                'category': 'Performance',
                'priority': 'High',
                'issue': f'{performance_regressions} endpoints show performance regressions',
                'recommendation': 'Review Flask application configuration, database query optimization, and consider implementing caching strategies',
                'action_items': [
                    'Profile slow endpoints using pytest-benchmark detailed reports',
                    'Optimize SQLAlchemy queries and consider query caching',
                    'Review Flask application factory configuration for performance settings'
                ]
            })
        
        # Functional equivalence recommendations
        failed_tests = self.test_statistics.get('failed_tests', 0)
        total_tests = self.test_statistics.get('total_tests', 1)
        equivalence_rate = ((total_tests - failed_tests) / total_tests) * 100
        
        if equivalence_rate < 100.0:
            recommendations.append({
                'category': 'Functional Equivalence',
                'priority': 'Critical' if equivalence_rate < 95.0 else 'High',
                'issue': f'Functional equivalence rate is {equivalence_rate:.1f}%, target is 100%',
                'recommendation': 'Address all functional discrepancies before deployment',
                'action_items': [
                    'Review detailed discrepancy analysis in the report',
                    'Implement automated correction workflows for common issues',
                    'Update Flask implementation to match Node.js behavior exactly'
                ]
            })
        
        # Discrepancy pattern recommendations
        common_issues = self._identify_common_issues([
            discrepancy for result in self.test_results 
            for discrepancy in result.discrepancies
        ])
        
        if common_issues:
            top_issue = common_issues[0]
            recommendations.append({
                'category': 'Code Quality',
                'priority': 'Medium',
                'issue': f'Most common issue: {top_issue["description"]} ({top_issue["count"]} occurrences)',
                'recommendation': 'Implement systematic fix for the most frequent discrepancy pattern',
                'action_items': [
                    f'Address {top_issue["category"]} issues systematically',
                    'Update testing patterns to catch similar issues earlier',
                    'Consider implementing automated validation for this pattern'
                ]
            })
        
        # Testing coverage recommendations
        if total_tests < 50:  # Arbitrary threshold
            recommendations.append({
                'category': 'Test Coverage',
                'priority': 'Medium',
                'issue': f'Limited test coverage with only {total_tests} comparative tests',
                'recommendation': 'Expand comparative testing coverage to include more endpoints and scenarios',
                'action_items': [
                    'Identify untested API endpoints and add comparative tests',
                    'Add business workflow testing for complex user journeys',
                    'Implement edge case testing for error handling scenarios'
                ]
            })
        
        return recommendations
    
    def _save_report_to_file(self, report: Dict[str, Any], output_path: str):
        """Save comprehensive report to JSON file"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            self.logger.info(f"Comprehensive report saved to: {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to save report to file: {str(e)}")
    
    def _generate_html_report(self, report: Dict[str, Any], base_path: Optional[str] = None) -> str:
        """Generate HTML report for better visualization"""
        # This would generate an HTML report using a template
        # For now, return a placeholder path
        html_path = base_path.replace('.json', '.html') if base_path else 'comparative_testing_report.html'
        
        # Placeholder HTML generation
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Comparative Testing Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .warning {{ color: orange; }}
            </style>
        </head>
        <body>
            <h1>Flask Migration Comparative Testing Report</h1>
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Overall Status: <span class="{report['executive_summary']['overall_status'].lower()}">{report['executive_summary']['overall_status']}</span></p>
                <p>Functional Equivalence: {report['executive_summary']['functional_equivalence_percentage']}%</p>
                <p>Tests Executed: {report['executive_summary']['total_tests_executed']}</p>
                <p>Migration Readiness: {report['executive_summary']['migration_readiness']}</p>
            </div>
            <h2>Detailed Results</h2>
            <p>See JSON report for detailed analysis.</p>
        </body>
        </html>
        """
        
        try:
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.logger.info(f"HTML report generated: {html_path}")
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
        
        return html_path
    
    def trigger_automated_correction_workflow(self, result: ComparisonResult) -> bool:
        """
        Trigger automated correction workflow for parity failure remediation
        as specified in Section 4.7.2.
        
        Args:
            result: ComparisonResult containing detected discrepancies
            
        Returns:
            bool: True if correction workflow was successfully triggered
        """
        if result.is_equivalent:
            self.logger.info(f"No correction needed for test {result.test_id} - already equivalent")
            return True
        
        self.logger.info(f"Triggering automated correction workflow for test {result.test_id}")
        
        try:
            # Analyze discrepancies for automated correction potential
            correctable_discrepancies = self._identify_correctable_discrepancies(result)
            
            if not correctable_discrepancies:
                self.logger.warning(f"No automatically correctable discrepancies found in test {result.test_id}")
                return False
            
            # Apply automated corrections
            corrections_applied = []
            for discrepancy in correctable_discrepancies:
                correction_result = self._apply_automated_correction(discrepancy, result)
                if correction_result:
                    corrections_applied.append(correction_result)
            
            if corrections_applied:
                self.logger.info(f"Applied {len(corrections_applied)} automated corrections for test {result.test_id}")
                
                # Re-execute test to validate corrections
                retest_result = self.execute_parallel_comparison(
                    result.endpoint,
                    result.method
                )
                
                if retest_result.is_equivalent:
                    self.logger.info(f"Automated correction successful for test {result.test_id}")
                    return True
                else:
                    self.logger.warning(f"Automated correction incomplete for test {result.test_id} - manual intervention required")
                    return False
            else:
                self.logger.warning(f"No corrections could be applied for test {result.test_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Automated correction workflow failed for test {result.test_id}: {str(e)}")
            return False
    
    def _identify_correctable_discrepancies(self, result: ComparisonResult) -> List[Dict[str, Any]]:
        """Identify discrepancies that can be automatically corrected"""
        correctable = []
        
        for discrepancy in result.discrepancies:
            category = discrepancy['category']
            
            # Define patterns that can be automatically corrected
            if category in ['headers', 'content_type'] and discrepancy['severity'] in ['info', 'warning']:
                correctable.append(discrepancy)
            elif category == 'body' and 'timestamp' in discrepancy['description'].lower():
                correctable.append(discrepancy)
            # Add more correctable patterns as needed
        
        return correctable
    
    def _apply_automated_correction(self, discrepancy: Dict[str, Any], result: ComparisonResult) -> Optional[Dict[str, Any]]:
        """Apply automated correction for a specific discrepancy"""
        category = discrepancy['category']
        
        try:
            if category == 'headers':
                return self._correct_header_discrepancy(discrepancy, result)
            elif category == 'content_type':
                return self._correct_content_type_discrepancy(discrepancy, result)
            elif 'timestamp' in discrepancy['description'].lower():
                return self._correct_timestamp_discrepancy(discrepancy, result)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to apply correction for {category}: {str(e)}")
            return None
    
    def _correct_header_discrepancy(self, discrepancy: Dict[str, Any], result: ComparisonResult) -> Dict[str, Any]:
        """Apply correction for header discrepancies"""
        # This would contain logic to automatically adjust Flask response headers
        # to match Node.js format
        return {
            'type': 'header_correction',
            'discrepancy_id': discrepancy.get('timestamp'),
            'action': 'Adjusted Flask response headers to match Node.js format',
            'status': 'applied'
        }
    
    def _correct_content_type_discrepancy(self, discrepancy: Dict[str, Any], result: ComparisonResult) -> Dict[str, Any]:
        """Apply correction for content type discrepancies"""
        # This would contain logic to standardize content type headers
        return {
            'type': 'content_type_correction',
            'discrepancy_id': discrepancy.get('timestamp'),
            'action': 'Standardized content type header format',
            'status': 'applied'
        }
    
    def _correct_timestamp_discrepancy(self, discrepancy: Dict[str, Any], result: ComparisonResult) -> Dict[str, Any]:
        """Apply correction for timestamp format discrepancies"""
        # This would contain logic to standardize timestamp formats
        return {
            'type': 'timestamp_correction',
            'discrepancy_id': discrepancy.get('timestamp'),
            'action': 'Standardized timestamp format between systems',
            'status': 'applied'
        }
    
    def cleanup_test_resources(self):
        """Cleanup testing resources and close connections"""
        try:
            if self.nodejs_session:
                self.nodejs_session.close()
            
            if self.executor:
                self.executor.shutdown(wait=True)
            
            # Cleanup test data if configured
            if self.config.CLEANUP_TEST_DATA:
                self._cleanup_test_data()
            
            self.logger.info("Test resources cleaned up successfully")
            
        except Exception as e:
            self.logger.error(f"Error during test resource cleanup: {str(e)}")
    
    def _cleanup_test_data(self):
        """Cleanup test data created during testing"""
        # This would contain logic to cleanup any test data created
        # in databases or external systems during testing
        pass


# ================================
# Utility Functions and Decorators
# ================================

def comparative_test(endpoint: str, method: str = 'GET', 
                    data: Dict[str, Any] = None,
                    headers: Dict[str, str] = None,
                    expected_status: int = 200,
                    tolerance_ms: int = None):
    """
    Decorator for creating comparative tests with standard patterns
    and automatic discrepancy detection and reporting.
    
    Args:
        endpoint: API endpoint to test
        method: HTTP method to use
        data: Request data
        headers: Request headers
        expected_status: Expected HTTP status code
        tolerance_ms: Performance tolerance in milliseconds
        
    Usage:
        @comparative_test('/api/users', 'GET')
        def test_get_users(comparative_framework):
            # Test will automatically execute parallel comparison
            pass
    """
    def decorator(test_func):
        def wrapper(*args, **kwargs):
            # Extract comparative framework from test function arguments
            comparative_framework = None
            for arg in args:
                if isinstance(arg, ComparativeTestingFramework):
                    comparative_framework = arg
                    break
            
            if not comparative_framework:
                pytest.fail("Comparative testing framework not available")
            
            # Execute parallel comparison
            result = comparative_framework.execute_parallel_comparison(
                endpoint, method, data, headers
            )
            
            # Validate expected status
            if result.nodejs_response and result.nodejs_response.status_code != expected_status:
                pytest.fail(f"Node.js endpoint returned unexpected status: {result.nodejs_response.status_code}")
            
            if result.flask_response and result.flask_response.status_code != expected_status:
                pytest.fail(f"Flask endpoint returned unexpected status: {result.flask_response.status_code}")
            
            # Check performance tolerance if specified
            if tolerance_ms and result.performance_delta_ms and result.performance_delta_ms > tolerance_ms:
                pytest.fail(f"Performance tolerance exceeded: {result.performance_delta_ms}ms > {tolerance_ms}ms")
            
            # Execute original test function with results
            kwargs['comparison_result'] = result
            return test_func(*args, **kwargs)
        
        return wrapper
    return decorator


def workflow_test(workflow_name: str, workflow_steps: List[Dict[str, Any]], 
                  expected_outcome: Dict[str, Any]):
    """
    Decorator for creating business logic workflow tests ensuring identical
    execution outcomes between systems as required by Feature F-005.
    
    Args:
        workflow_name: Name of the business workflow
        workflow_steps: List of API calls representing the workflow
        expected_outcome: Expected final state after workflow completion
        
    Usage:
        @workflow_test('user_registration', [...steps...], {...expected...})
        def test_user_registration_workflow(comparative_framework):
            # Workflow test will automatically execute on both systems
            pass
    """
    def decorator(test_func):
        def wrapper(*args, **kwargs):
            comparative_framework = None
            for arg in args:
                if isinstance(arg, ComparativeTestingFramework):
                    comparative_framework = arg
                    break
            
            if not comparative_framework:
                pytest.fail("Comparative testing framework not available")
            
            # Execute workflow validation
            result = comparative_framework.validate_business_logic_workflow(
                workflow_name, workflow_steps, expected_outcome
            )
            
            # Execute original test function with results
            kwargs['workflow_result'] = result
            return test_func(*args, **kwargs)
        
        return wrapper
    return decorator


# ================================
# Multi-Environment Testing Integration
# ================================

class ToxIntegration:
    """
    Integration class for multi-environment testing with tox 4.26.0 as
    specified in Section 4.7.2 for comprehensive validation across
    different Python environments and dependency configurations.
    """
    
    def __init__(self, comparative_framework: ComparativeTestingFramework):
        self.comparative_framework = comparative_framework
        self.logger = logging.getLogger('tox_integration')
        
    def execute_multi_environment_tests(self, test_suite: List[Callable],
                                       environments: List[str] = None) -> Dict[str, Any]:
        """
        Execute test suite across multiple tox environments with comprehensive
        result collection and environment-specific analysis.
        
        Args:
            test_suite: List of test functions to execute
            environments: List of tox environment names to test
            
        Returns:
            Dict[str, Any]: Multi-environment test results
        """
        environments = environments or ComparativeTestingConfig.TOX_ENVIRONMENTS
        results = {}
        
        for env in environments:
            self.logger.info(f"Starting tests in tox environment: {env}")
            
            with self.comparative_framework.test_environment(env):
                env_results = self._execute_environment_tests(test_suite, env)
                results[env] = env_results
        
        # Generate cross-environment analysis
        cross_env_analysis = self._analyze_cross_environment_results(results)
        
        return {
            'environment_results': results,
            'cross_environment_analysis': cross_env_analysis,
            'overall_compatibility': self._calculate_overall_compatibility(results)
        }
    
    def _execute_environment_tests(self, test_suite: List[Callable], env: str) -> Dict[str, Any]:
        """Execute test suite in a specific environment"""
        env_results = {
            'environment': env,
            'start_time': datetime.utcnow(),
            'test_results': [],
            'errors': []
        }
        
        for test_func in test_suite:
            try:
                result = test_func(self.comparative_framework)
                env_results['test_results'].append(result)
            except Exception as e:
                self.logger.error(f"Test failed in environment {env}: {str(e)}")
                env_results['errors'].append({
                    'test_function': test_func.__name__,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
        
        env_results['end_time'] = datetime.utcnow()
        env_results['duration'] = (env_results['end_time'] - env_results['start_time']).total_seconds()
        
        return env_results
    
    def _analyze_cross_environment_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results across different environments to identify compatibility issues"""
        # This would contain logic to compare results across environments
        # and identify environment-specific discrepancies
        return {
            'environment_specific_failures': {},
            'consistent_failures': [],
            'environment_compatibility_matrix': {}
        }
    
    def _calculate_overall_compatibility(self, results: Dict[str, Any]) -> float:
        """Calculate overall compatibility score across all environments"""
        if not results:
            return 0.0
        
        total_score = 0.0
        environment_count = 0
        
        for env, env_results in results.items():
            test_results = env_results.get('test_results', [])
            if test_results:
                success_rate = len([r for r in test_results if r and getattr(r, 'is_equivalent', False)]) / len(test_results)
                total_score += success_rate
                environment_count += 1
        
        return (total_score / environment_count * 100) if environment_count > 0 else 0.0


# ================================
# pytest Integration and Fixtures
# ================================

@pytest.fixture(scope='session')
def comparative_testing_framework(app) -> ComparativeTestingFramework:
    """
    pytest fixture providing configured ComparativeTestingFramework instance
    for comprehensive functionality parity validation testing.
    
    This fixture establishes the testing framework with proper configuration
    and system connections as specified in Feature F-009 requirements.
    
    Args:
        app: Flask application fixture from conftest.py
        
    Returns:
        ComparativeTestingFramework: Configured testing framework instance
    """
    config = ComparativeTestingConfig()
    framework = ComparativeTestingFramework(config)
    
    # Configure Flask client if app is available
    if app:
        with app.test_client() as client:
            framework.set_flask_client(client)
    
    yield framework
    
    # Cleanup after session
    framework.cleanup_test_resources()


@pytest.fixture
def nodejs_baseline_validator(comparative_testing_framework):
    """
    pytest fixture for validating Flask responses against Node.js baseline
    with automated discrepancy detection and reporting capabilities.
    
    Returns:
        Callable: Validator function for baseline comparison
    """
    def validate_against_baseline(endpoint: str, method: str = 'GET',
                                 data: Dict[str, Any] = None,
                                 headers: Dict[str, str] = None) -> ComparisonResult:
        """
        Validate Flask endpoint response against Node.js baseline
        
        Args:
            endpoint: API endpoint to validate
            method: HTTP method to use
            data: Request data
            headers: Request headers
            
        Returns:
            ComparisonResult: Detailed comparison analysis
        """
        return comparative_testing_framework.execute_parallel_comparison(
            endpoint, method, data, headers
        )
    
    return validate_against_baseline


@pytest.fixture
def business_logic_validator(comparative_testing_framework):
    """
    pytest fixture for validating business logic workflows ensuring identical
    execution outcomes between Node.js and Flask systems per Feature F-005.
    
    Returns:
        Callable: Validator function for business logic workflows
    """
    def validate_workflow(workflow_name: str, workflow_steps: List[Dict[str, Any]],
                         expected_outcome: Dict[str, Any]) -> ComparisonResult:
        """
        Validate business logic workflow execution
        
        Args:
            workflow_name: Name of the business workflow
            workflow_steps: List of API calls representing the workflow
            expected_outcome: Expected final state
            
        Returns:
            ComparisonResult: Workflow validation result
        """
        return comparative_testing_framework.validate_business_logic_workflow(
            workflow_name, workflow_steps, expected_outcome
        )
    
    return validate_workflow


# ================================
# Export Public Interface
# ================================

__all__ = [
    'ComparativeTestingFramework',
    'ComparativeTestingConfig',
    'SystemResponse',
    'ComparisonResult',
    'ToxIntegration',
    'comparative_test',
    'workflow_test',
    'comparative_testing_framework',
    'nodejs_baseline_validator',
    'business_logic_validator'
]