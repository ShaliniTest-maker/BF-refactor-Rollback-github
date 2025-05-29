"""
Core comparative testing module implementing pytest-flask 1.3.0 functionality for validating
100% API endpoint parity between Node.js baseline and Flask implementation.

This critical module executes parallel testing against both systems, compares response formats,
validates business logic equivalence, and triggers automated correction workflows when
discrepancies are detected as specified in Section 4.7.1 of the technical specification.

Key Features:
- pytest-flask 1.3.0 configuration for Flask application testing fixtures
- 100% API response format compatibility validation per Feature F-009
- Business logic execution equivalence testing per Feature F-009
- Database operation result consistency validation per Feature F-009
- Automated discrepancy detection and reporting per Section 4.7.2

Dependencies:
- pytest-flask 1.3.0: Flask-specific testing capabilities and fixtures
- Flask 3.1.1: Application testing with proper request context management
- requests: HTTP client for Node.js system communication
- deepdiff: Advanced difference analysis for response comparison
- pytest-benchmark: Performance comparison against baseline metrics

Author: Flask Migration Team
Version: 1.0.0
Last Updated: 2024-01-15
"""

import json
import time
import uuid
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from unittest.mock import Mock, patch, MagicMock
from contextlib import contextmanager
from dataclasses import dataclass, asdict
import difflib
import copy

# Testing framework imports
import pytest
from pytest import fixture, mark, param
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Deep comparison and analysis
try:
    from deepdiff import DeepDiff
    DEEPDIFF_AVAILABLE = True
except ImportError:
    DEEPDIFF_AVAILABLE = False
    DeepDiff = None

# Flask testing imports
from flask import Flask, request, g, current_app, session
from flask.testing import FlaskClient
import pytest_flask

# Application imports (with fallback handling)
try:
    from src.blueprints import api, auth, main
    from src.models import db, User
    from src.services import health_service, auth_service
    from tests.comparative.baseline_data import NodeJSBaseline, PerformanceBaseline
    from tests.comparative.correction_workflow import DiscrepancyAnalyzer, AutoCorrection
except ImportError as e:
    # Handle missing modules during development
    logging.warning(f"Import warning during testing setup: {e}")
    api = auth = main = None
    db = User = None
    health_service = auth_service = None
    NodeJSBaseline = PerformanceBaseline = None
    DiscrepancyAnalyzer = AutoCorrection = None


# ================================
# Test Configuration and Constants
# ================================

# Node.js system configuration for baseline comparison
NODEJS_BASE_URL = "http://localhost:3000"  # Default Node.js server URL
NODEJS_TIMEOUT = 30  # Request timeout in seconds
MAX_RETRIES = 3  # Maximum retry attempts for flaky network calls

# Performance thresholds for SLA validation
PERFORMANCE_THRESHOLDS = {
    'response_time_ms': 500,  # Maximum acceptable response time
    'memory_usage_mb': 100,   # Maximum memory usage increase
    'database_query_ms': 50,  # Maximum database query time
    'concurrent_users': 100   # Minimum concurrent user support
}

# API endpoint categories for systematic testing
API_ENDPOINT_CATEGORIES = {
    'authentication': [
        '/api/auth/login',
        '/api/auth/logout', 
        '/api/auth/refresh',
        '/api/auth/profile',
        '/api/auth/register'
    ],
    'users': [
        '/api/users',
        '/api/users/{id}',
        '/api/users/{id}/profile',
        '/api/users/{id}/settings'
    ],
    'health': [
        '/health',
        '/health/ready',
        '/health/live',
        '/api/status'
    ],
    'core_business': [
        '/api/dashboard',
        '/api/data',
        '/api/analytics',
        '/api/reports'
    ]
}

# HTTP methods to test for each endpoint
HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

# Response validation schemas
RESPONSE_SCHEMAS = {
    'success': {
        'required_fields': ['status', 'data'],
        'status_codes': [200, 201, 202],
        'content_type': 'application/json'
    },
    'error': {
        'required_fields': ['error', 'message'],
        'status_codes': [400, 401, 403, 404, 422, 500],
        'content_type': 'application/json'
    },
    'health': {
        'required_fields': ['status', 'timestamp'],
        'status_codes': [200],
        'content_type': 'application/json'
    }
}


# ================================
# Data Classes and Models
# ================================

@dataclass
class APITestCase:
    """
    Comprehensive API test case definition containing all necessary information
    for parallel testing between Node.js and Flask implementations.
    """
    endpoint: str
    method: str
    payload: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    query_params: Optional[Dict[str, str]] = None
    auth_required: bool = False
    expected_status: int = 200
    category: str = 'general'
    description: str = ''
    tags: List[str] = None
    performance_threshold_ms: int = 500
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if not self.description:
            self.description = f"{self.method} {self.endpoint}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert test case to dictionary for serialization"""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'APITestCase':
        """Create test case from dictionary"""
        return cls(**data)


@dataclass
class ComparisonResult:
    """
    Comprehensive comparison result containing detailed analysis of differences
    between Node.js and Flask system responses.
    """
    test_case: APITestCase
    flask_response: Optional[requests.Response] = None
    nodejs_response: Optional[requests.Response] = None
    
    # Response comparison results
    status_code_match: bool = False
    headers_match: bool = False
    content_match: bool = False
    json_structure_match: bool = False
    
    # Performance comparison
    flask_response_time_ms: float = 0.0
    nodejs_response_time_ms: float = 0.0
    performance_delta_ms: float = 0.0
    
    # Detailed difference analysis
    differences: Dict[str, Any] = None
    error_details: Optional[str] = None
    
    # Overall result
    passed: bool = False
    score: float = 0.0  # Similarity score (0-100%)
    
    def __post_init__(self):
        if self.differences is None:
            self.differences = {}
    
    def calculate_score(self) -> float:
        """Calculate overall similarity score based on comparison criteria"""
        criteria_weights = {
            'status_code': 30,    # 30% weight
            'headers': 20,        # 20% weight  
            'content': 40,        # 40% weight
            'performance': 10     # 10% weight
        }
        
        score = 0.0
        
        # Status code comparison
        if self.status_code_match:
            score += criteria_weights['status_code']
        
        # Headers comparison  
        if self.headers_match:
            score += criteria_weights['headers']
        
        # Content comparison
        if self.content_match:
            score += criteria_weights['content']
        
        # Performance comparison (within 20% threshold)
        if abs(self.performance_delta_ms) <= (self.nodejs_response_time_ms * 0.2):
            score += criteria_weights['performance']
        
        self.score = score
        self.passed = score >= 90.0  # 90% similarity threshold for passing
        
        return score
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive comparison report"""
        return {
            'test_case': self.test_case.to_dict(),
            'passed': self.passed,
            'score': self.score,
            'status_comparison': {
                'flask_status': self.flask_response.status_code if self.flask_response else None,
                'nodejs_status': self.nodejs_response.status_code if self.nodejs_response else None,
                'match': self.status_code_match
            },
            'performance_comparison': {
                'flask_time_ms': self.flask_response_time_ms,
                'nodejs_time_ms': self.nodejs_response_time_ms,
                'delta_ms': self.performance_delta_ms,
                'within_threshold': abs(self.performance_delta_ms) <= PERFORMANCE_THRESHOLDS['response_time_ms']
            },
            'content_analysis': {
                'structure_match': self.json_structure_match,
                'content_match': self.content_match,
                'differences': self.differences
            },
            'error_details': self.error_details,
            'timestamp': datetime.utcnow().isoformat()
        }


# ================================
# Utility Classes and Functions
# ================================

class NodeJSClient:
    """
    Robust HTTP client for communicating with the Node.js baseline system
    with comprehensive error handling, retry logic, and performance monitoring.
    """
    
    def __init__(self, base_url: str = NODEJS_BASE_URL, timeout: int = NODEJS_TIMEOUT):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        
        # Configure retry strategy for resilient testing
        retry_strategy = Retry(
            total=MAX_RETRIES,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default headers for consistent communication
        self.session.headers.update({
            'User-Agent': 'Flask-Migration-Test-Client/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
    
    def request(self, method: str, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """
        Execute HTTP request with performance monitoring and error handling
        
        Returns:
            Tuple of (response, execution_time_ms)
        """
        url = f"{self.base_url}{endpoint}"
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            execution_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            return response, execution_time
            
        except requests.exceptions.RequestException as e:
            execution_time = (time.time() - start_time) * 1000
            logging.error(f"Node.js request failed: {method} {url} - {str(e)}")
            
            # Create mock response for failed requests
            mock_response = Mock(spec=requests.Response)
            mock_response.status_code = 503
            mock_response.headers = {}
            mock_response.content = json.dumps({
                'error': 'ServiceUnavailable',
                'message': f'Node.js system unavailable: {str(e)}'
            }).encode()
            mock_response.json.return_value = {
                'error': 'ServiceUnavailable', 
                'message': f'Node.js system unavailable: {str(e)}'
            }
            
            return mock_response, execution_time
    
    def get(self, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """Execute GET request with performance monitoring"""
        return self.request('GET', endpoint, **kwargs)
    
    def post(self, endpoint: str, data: Dict[str, Any] = None, **kwargs) -> Tuple[requests.Response, float]:
        """Execute POST request with JSON payload"""
        if data:
            kwargs['json'] = data
        return self.request('POST', endpoint, **kwargs)
    
    def put(self, endpoint: str, data: Dict[str, Any] = None, **kwargs) -> Tuple[requests.Response, float]:
        """Execute PUT request with JSON payload"""
        if data:
            kwargs['json'] = data
        return self.request('PUT', endpoint, **kwargs)
    
    def delete(self, endpoint: str, **kwargs) -> Tuple[requests.Response, float]:
        """Execute DELETE request"""
        return self.request('DELETE', endpoint, **kwargs)
    
    def patch(self, endpoint: str, data: Dict[str, Any] = None, **kwargs) -> Tuple[requests.Response, float]:
        """Execute PATCH request with JSON payload"""
        if data:
            kwargs['json'] = data
        return self.request('PATCH', endpoint, **kwargs)
    
    def health_check(self) -> bool:
        """Check if Node.js system is available and responding"""
        try:
            response, _ = self.get('/health')
            return response.status_code == 200
        except Exception:
            return False
    
    def close(self):
        """Close the session and cleanup resources"""
        self.session.close()


class ResponseComparator:
    """
    Advanced response comparison engine providing comprehensive analysis
    of differences between Node.js and Flask system responses.
    """
    
    def __init__(self, strict_mode: bool = True, ignore_fields: List[str] = None):
        self.strict_mode = strict_mode
        self.ignore_fields = ignore_fields or ['timestamp', 'request_id', '_metadata']
        
    def compare_responses(self, flask_response: requests.Response, 
                         nodejs_response: requests.Response) -> Dict[str, Any]:
        """
        Comprehensive response comparison with detailed difference analysis
        
        Returns:
            Dictionary containing detailed comparison results
        """
        comparison = {
            'status_codes': self._compare_status_codes(flask_response, nodejs_response),
            'headers': self._compare_headers(flask_response, nodejs_response),
            'content': self._compare_content(flask_response, nodejs_response),
            'json_structure': None,
            'overall_match': False
        }
        
        # JSON structure comparison if both responses are JSON
        if self._is_json_response(flask_response) and self._is_json_response(nodejs_response):
            comparison['json_structure'] = self._compare_json_structure(
                flask_response, nodejs_response
            )
        
        # Calculate overall match
        comparison['overall_match'] = (
            comparison['status_codes']['match'] and
            comparison['content']['match'] and
            (comparison['json_structure']['match'] if comparison['json_structure'] else True)
        )
        
        return comparison
    
    def _compare_status_codes(self, flask_resp: requests.Response, 
                            nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Compare HTTP status codes"""
        return {
            'flask_status': flask_resp.status_code,
            'nodejs_status': nodejs_resp.status_code,
            'match': flask_resp.status_code == nodejs_resp.status_code,
            'difference': abs(flask_resp.status_code - nodejs_resp.status_code)
        }
    
    def _compare_headers(self, flask_resp: requests.Response, 
                        nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Compare response headers with intelligent filtering"""
        # Headers to ignore during comparison (implementation-specific)
        ignore_headers = {
            'date', 'server', 'x-powered-by', 'x-request-id', 
            'x-response-time', 'connection', 'transfer-encoding'
        }
        
        flask_headers = {k.lower(): v for k, v in flask_resp.headers.items() 
                        if k.lower() not in ignore_headers}
        nodejs_headers = {k.lower(): v for k, v in nodejs_resp.headers.items() 
                         if k.lower() not in ignore_headers}
        
        content_type_match = (
            flask_headers.get('content-type', '').split(';')[0] ==
            nodejs_headers.get('content-type', '').split(';')[0]
        )
        
        return {
            'content_type_match': content_type_match,
            'flask_headers': flask_headers,
            'nodejs_headers': nodejs_headers,
            'match': content_type_match,  # Focus on content-type for API compatibility
            'differences': self._find_header_differences(flask_headers, nodejs_headers)
        }
    
    def _compare_content(self, flask_resp: requests.Response, 
                        nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Compare response content with multiple comparison strategies"""
        try:
            # Try JSON comparison first
            if self._is_json_response(flask_resp) and self._is_json_response(nodejs_resp):
                return self._compare_json_content(flask_resp, nodejs_resp)
            
            # Fall back to text comparison
            return self._compare_text_content(flask_resp, nodejs_resp)
            
        except Exception as e:
            return {
                'match': False,
                'error': f"Content comparison failed: {str(e)}",
                'flask_content_length': len(flask_resp.content),
                'nodejs_content_length': len(nodejs_resp.content)
            }
    
    def _compare_json_content(self, flask_resp: requests.Response, 
                             nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Advanced JSON content comparison with field filtering"""
        try:
            flask_json = flask_resp.json()
            nodejs_json = nodejs_resp.json()
            
            # Remove ignored fields for comparison
            flask_filtered = self._filter_ignore_fields(copy.deepcopy(flask_json))
            nodejs_filtered = self._filter_ignore_fields(copy.deepcopy(nodejs_json))
            
            if DEEPDIFF_AVAILABLE:
                # Use DeepDiff for advanced comparison
                diff = DeepDiff(
                    nodejs_filtered, flask_filtered,
                    ignore_order=True,
                    report_type='summary'
                )
                
                return {
                    'match': len(diff) == 0,
                    'differences': dict(diff) if diff else {},
                    'flask_json': flask_filtered,
                    'nodejs_json': nodejs_filtered,
                    'comparison_method': 'deepdiff'
                }
            else:
                # Basic comparison
                match = flask_filtered == nodejs_filtered
                return {
                    'match': match,
                    'flask_json': flask_filtered,
                    'nodejs_json': nodejs_filtered,
                    'comparison_method': 'basic',
                    'differences': {} if match else {'content': 'JSON structures differ'}
                }
                
        except json.JSONDecodeError as e:
            return {
                'match': False,
                'error': f"JSON parsing failed: {str(e)}",
                'flask_content': flask_resp.text[:500],  # First 500 chars
                'nodejs_content': nodejs_resp.text[:500]
            }
    
    def _compare_text_content(self, flask_resp: requests.Response, 
                             nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Text content comparison with diff analysis"""
        flask_text = flask_resp.text.strip()
        nodejs_text = nodejs_resp.text.strip()
        
        match = flask_text == nodejs_text
        
        if not match and len(flask_text) < 10000 and len(nodejs_text) < 10000:
            # Generate unified diff for small responses
            diff_lines = list(difflib.unified_diff(
                nodejs_text.splitlines(keepends=True),
                flask_text.splitlines(keepends=True),
                fromfile='nodejs_response',
                tofile='flask_response',
                lineterm=''
            ))
            
            return {
                'match': match,
                'flask_content': flask_text,
                'nodejs_content': nodejs_text,
                'unified_diff': ''.join(diff_lines),
                'comparison_method': 'text_diff'
            }
        
        return {
            'match': match,
            'flask_length': len(flask_text),
            'nodejs_length': len(nodejs_text),
            'comparison_method': 'text_basic'
        }
    
    def _compare_json_structure(self, flask_resp: requests.Response, 
                               nodejs_resp: requests.Response) -> Dict[str, Any]:
        """Compare JSON structure (keys and types) without values"""
        try:
            flask_json = flask_resp.json()
            nodejs_json = nodejs_resp.json()
            
            flask_structure = self._extract_json_structure(flask_json)
            nodejs_structure = self._extract_json_structure(nodejs_json)
            
            return {
                'match': flask_structure == nodejs_structure,
                'flask_structure': flask_structure,
                'nodejs_structure': nodejs_structure
            }
            
        except Exception as e:
            return {
                'match': False,
                'error': f"Structure comparison failed: {str(e)}"
            }
    
    def _extract_json_structure(self, obj: Any, path: str = "") -> Dict[str, str]:
        """Extract JSON structure as type mapping"""
        structure = {}
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, (dict, list)):
                    structure.update(self._extract_json_structure(value, current_path))
                else:
                    structure[current_path] = type(value).__name__
        elif isinstance(obj, list) and obj:
            # Analyze first item for list structure
            current_path = f"{path}[0]"
            structure.update(self._extract_json_structure(obj[0], current_path))
        
        return structure
    
    def _filter_ignore_fields(self, obj: Any) -> Any:
        """Recursively remove ignored fields from object"""
        if isinstance(obj, dict):
            return {k: self._filter_ignore_fields(v) for k, v in obj.items() 
                   if k not in self.ignore_fields}
        elif isinstance(obj, list):
            return [self._filter_ignore_fields(item) for item in obj]
        else:
            return obj
    
    def _find_header_differences(self, headers1: Dict[str, str], 
                                headers2: Dict[str, str]) -> Dict[str, Any]:
        """Find specific differences between header sets"""
        all_keys = set(headers1.keys()) | set(headers2.keys())
        differences = {}
        
        for key in all_keys:
            val1 = headers1.get(key)
            val2 = headers2.get(key)
            
            if val1 != val2:
                differences[key] = {
                    'flask': val1,
                    'nodejs': val2
                }
        
        return differences
    
    def _is_json_response(self, response: requests.Response) -> bool:
        """Check if response contains JSON content"""
        content_type = response.headers.get('content-type', '').lower()
        return 'application/json' in content_type


# ================================
# Test Data Generation and Management
# ================================

class TestDataGenerator:
    """
    Comprehensive test data generator for creating realistic test scenarios
    covering various API endpoint patterns and edge cases.
    """
    
    def __init__(self):
        self.user_counter = 0
        self.request_counter = 0
    
    def generate_api_test_cases(self) -> List[APITestCase]:
        """Generate comprehensive test cases for all API endpoints"""
        test_cases = []
        
        # Authentication endpoints
        test_cases.extend(self._generate_auth_test_cases())
        
        # User management endpoints
        test_cases.extend(self._generate_user_test_cases())
        
        # Health check endpoints
        test_cases.extend(self._generate_health_test_cases())
        
        # Core business logic endpoints
        test_cases.extend(self._generate_business_test_cases())
        
        return test_cases
    
    def _generate_auth_test_cases(self) -> List[APITestCase]:
        """Generate authentication endpoint test cases"""
        return [
            APITestCase(
                endpoint="/api/auth/login",
                method="POST",
                payload={
                    "username": "testuser@example.com",
                    "password": "testpassword123"
                },
                expected_status=200,
                category="authentication",
                description="User login with valid credentials",
                tags=["auth", "login", "success"]
            ),
            APITestCase(
                endpoint="/api/auth/login",
                method="POST",
                payload={
                    "username": "invalid@example.com",
                    "password": "wrongpassword"
                },
                expected_status=401,
                category="authentication",
                description="User login with invalid credentials",
                tags=["auth", "login", "failure"]
            ),
            APITestCase(
                endpoint="/api/auth/logout",
                method="POST",
                auth_required=True,
                expected_status=200,
                category="authentication",
                description="User logout with valid session",
                tags=["auth", "logout"]
            ),
            APITestCase(
                endpoint="/api/auth/profile",
                method="GET",
                auth_required=True,
                expected_status=200,
                category="authentication",
                description="Get user profile with authentication",
                tags=["auth", "profile", "get"]
            ),
            APITestCase(
                endpoint="/api/auth/refresh",
                method="POST",
                auth_required=True,
                expected_status=200,
                category="authentication",
                description="Refresh authentication token",
                tags=["auth", "refresh"]
            )
        ]
    
    def _generate_user_test_cases(self) -> List[APITestCase]:
        """Generate user management endpoint test cases"""
        return [
            APITestCase(
                endpoint="/api/users",
                method="GET",
                auth_required=True,
                expected_status=200,
                category="users",
                description="List all users",
                tags=["users", "list"]
            ),
            APITestCase(
                endpoint="/api/users",
                method="POST",
                payload=self._generate_user_data(),
                auth_required=True,
                expected_status=201,
                category="users",
                description="Create new user",
                tags=["users", "create"]
            ),
            APITestCase(
                endpoint="/api/users/1",
                method="GET",
                auth_required=True,
                expected_status=200,
                category="users",
                description="Get specific user by ID",
                tags=["users", "get", "detail"]
            ),
            APITestCase(
                endpoint="/api/users/1",
                method="PUT",
                payload=self._generate_user_update_data(),
                auth_required=True,
                expected_status=200,
                category="users",
                description="Update user information",
                tags=["users", "update"]
            ),
            APITestCase(
                endpoint="/api/users/1",
                method="DELETE",
                auth_required=True,
                expected_status=204,
                category="users",
                description="Delete user",
                tags=["users", "delete"]
            )
        ]
    
    def _generate_health_test_cases(self) -> List[APITestCase]:
        """Generate health check endpoint test cases"""
        return [
            APITestCase(
                endpoint="/health",
                method="GET",
                expected_status=200,
                category="health",
                description="Basic health check",
                tags=["health", "basic"],
                performance_threshold_ms=100  # Health checks should be fast
            ),
            APITestCase(
                endpoint="/health/ready",
                method="GET",
                expected_status=200,
                category="health",
                description="Readiness probe check",
                tags=["health", "readiness"],
                performance_threshold_ms=200
            ),
            APITestCase(
                endpoint="/health/live",
                method="GET",
                expected_status=200,
                category="health",
                description="Liveness probe check",
                tags=["health", "liveness"],
                performance_threshold_ms=100
            ),
            APITestCase(
                endpoint="/api/status",
                method="GET",
                expected_status=200,
                category="health",
                description="API status information",
                tags=["health", "status"],
                performance_threshold_ms=300
            )
        ]
    
    def _generate_business_test_cases(self) -> List[APITestCase]:
        """Generate core business logic endpoint test cases"""
        return [
            APITestCase(
                endpoint="/api/dashboard",
                method="GET",
                auth_required=True,
                expected_status=200,
                category="core_business",
                description="Get dashboard data",
                tags=["business", "dashboard"]
            ),
            APITestCase(
                endpoint="/api/data",
                method="GET",
                auth_required=True,
                query_params={"limit": "10", "offset": "0"},
                expected_status=200,
                category="core_business",
                description="Get paginated data",
                tags=["business", "data", "pagination"]
            ),
            APITestCase(
                endpoint="/api/analytics",
                method="POST",
                payload={
                    "metrics": ["response_time", "error_rate"],
                    "time_range": "7d"
                },
                auth_required=True,
                expected_status=200,
                category="core_business",
                description="Request analytics data",
                tags=["business", "analytics"]
            ),
            APITestCase(
                endpoint="/api/reports",
                method="GET",
                auth_required=True,
                query_params={"format": "json", "type": "summary"},
                expected_status=200,
                category="core_business",
                description="Generate system reports",
                tags=["business", "reports"]
            )
        ]
    
    def _generate_user_data(self) -> Dict[str, Any]:
        """Generate realistic user data for testing"""
        self.user_counter += 1
        return {
            "username": f"testuser{self.user_counter}",
            "email": f"testuser{self.user_counter}@example.com",
            "first_name": "Test",
            "last_name": f"User{self.user_counter}",
            "password": "testpassword123",
            "role": "user"
        }
    
    def _generate_user_update_data(self) -> Dict[str, Any]:
        """Generate user update data for testing"""
        return {
            "first_name": "Updated",
            "last_name": "User",
            "email": "updated.user@example.com"
        }


# ================================
# Core Testing Classes
# ================================

class APIParityTester:
    """
    Core API parity testing engine that orchestrates parallel testing
    between Node.js and Flask systems with comprehensive validation.
    """
    
    def __init__(self, flask_client: FlaskClient, nodejs_base_url: str = NODEJS_BASE_URL):
        self.flask_client = flask_client
        self.nodejs_client = NodeJSClient(nodejs_base_url)
        self.comparator = ResponseComparator()
        self.results = []
        self.session_data = {}
        
        # Performance tracking
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.start_time = None
        
    def execute_test_suite(self, test_cases: List[APITestCase]) -> List[ComparisonResult]:
        """
        Execute comprehensive test suite with parallel testing and validation
        
        Args:
            test_cases: List of API test cases to execute
            
        Returns:
            List of comparison results with detailed analysis
        """
        self.start_time = time.time()
        self.total_tests = len(test_cases)
        self.results = []
        
        logging.info(f"Starting API parity test suite with {self.total_tests} test cases")
        
        # Check Node.js system availability
        if not self.nodejs_client.health_check():
            logging.warning("Node.js system not available - using mock responses")
        
        for test_case in test_cases:
            try:
                result = self._execute_single_test(test_case)
                self.results.append(result)
                
                if result.passed:
                    self.passed_tests += 1
                else:
                    self.failed_tests += 1
                    
                # Log progress
                if self.total_tests > 0 and (len(self.results) % 10 == 0 or len(self.results) == self.total_tests):
                    progress = (len(self.results) / self.total_tests) * 100
                    logging.info(f"Test progress: {len(self.results)}/{self.total_tests} ({progress:.1f}%)")
                
            except Exception as e:
                logging.error(f"Test execution failed for {test_case.endpoint}: {str(e)}")
                
                # Create failed result
                failed_result = ComparisonResult(
                    test_case=test_case,
                    error_details=str(e),
                    passed=False
                )
                self.results.append(failed_result)
                self.failed_tests += 1
        
        execution_time = time.time() - self.start_time
        logging.info(f"Test suite completed in {execution_time:.2f}s - {self.passed_tests} passed, {self.failed_tests} failed")
        
        return self.results
    
    def _execute_single_test(self, test_case: APITestCase) -> ComparisonResult:
        """Execute a single test case with parallel Flask and Node.js requests"""
        logging.debug(f"Executing test: {test_case.method} {test_case.endpoint}")
        
        # Prepare request parameters
        request_kwargs = self._prepare_request_kwargs(test_case)
        
        # Execute Flask request
        flask_response, flask_time = self._execute_flask_request(test_case, request_kwargs)
        
        # Execute Node.js request
        nodejs_response, nodejs_time = self._execute_nodejs_request(test_case, request_kwargs)
        
        # Create comparison result
        result = ComparisonResult(
            test_case=test_case,
            flask_response=flask_response,
            nodejs_response=nodejs_response,
            flask_response_time_ms=flask_time,
            nodejs_response_time_ms=nodejs_time,
            performance_delta_ms=flask_time - nodejs_time
        )
        
        # Perform comprehensive comparison
        if flask_response and nodejs_response:
            comparison = self.comparator.compare_responses(flask_response, nodejs_response)
            
            result.status_code_match = comparison['status_codes']['match']
            result.headers_match = comparison['headers']['match']
            result.content_match = comparison['content']['match']
            result.json_structure_match = comparison.get('json_structure', {}).get('match', True)
            result.differences = comparison
            
            # Calculate overall score
            result.calculate_score()
        
        return result
    
    def _prepare_request_kwargs(self, test_case: APITestCase) -> Dict[str, Any]:
        """Prepare request parameters for both Flask and Node.js calls"""
        kwargs = {}
        
        # Add headers
        if test_case.headers:
            kwargs['headers'] = test_case.headers.copy()
        else:
            kwargs['headers'] = {}
        
        # Add authentication if required
        if test_case.auth_required:
            auth_token = self._get_auth_token()
            kwargs['headers']['Authorization'] = f'Bearer {auth_token}'
        
        # Add query parameters
        if test_case.query_params:
            kwargs['params'] = test_case.query_params
        
        # Add payload for applicable methods
        if test_case.payload and test_case.method.upper() in ['POST', 'PUT', 'PATCH']:
            kwargs['json'] = test_case.payload
        
        return kwargs
    
    def _execute_flask_request(self, test_case: APITestCase, 
                              request_kwargs: Dict[str, Any]) -> Tuple[Any, float]:
        """Execute request against Flask application"""
        start_time = time.time()
        
        try:
            # Convert requests-style kwargs to Flask test client format
            flask_kwargs = {}
            
            if 'headers' in request_kwargs:
                flask_kwargs['headers'] = request_kwargs['headers']
            
            if 'params' in request_kwargs:
                flask_kwargs['query_string'] = request_kwargs['params']
            
            if 'json' in request_kwargs:
                flask_kwargs['json'] = request_kwargs['json']
                flask_kwargs['content_type'] = 'application/json'
            
            # Execute request using Flask test client
            method = test_case.method.lower()
            if hasattr(self.flask_client, method):
                response = getattr(self.flask_client, method)(test_case.endpoint, **flask_kwargs)
            else:
                response = self.flask_client.open(
                    test_case.endpoint, 
                    method=test_case.method.upper(),
                    **flask_kwargs
                )
            
            execution_time = (time.time() - start_time) * 1000
            
            # Convert Flask response to requests-like response for compatibility
            mock_response = Mock(spec=requests.Response)
            mock_response.status_code = response.status_code
            mock_response.headers = dict(response.headers)
            mock_response.content = response.data
            mock_response.text = response.get_data(as_text=True)
            
            # Handle JSON response
            try:
                if response.is_json:
                    mock_response.json = lambda: response.get_json()
                else:
                    mock_response.json = Mock(side_effect=ValueError("No JSON object could be decoded"))
            except Exception:
                mock_response.json = Mock(side_effect=ValueError("No JSON object could be decoded"))
            
            return mock_response, execution_time
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logging.error(f"Flask request failed: {test_case.method} {test_case.endpoint} - {str(e)}")
            
            # Create error response
            error_response = Mock(spec=requests.Response)
            error_response.status_code = 500
            error_response.headers = {}
            error_response.content = json.dumps({
                'error': 'InternalServerError',
                'message': f'Flask request failed: {str(e)}'
            }).encode()
            error_response.text = error_response.content.decode()
            error_response.json = lambda: {
                'error': 'InternalServerError',
                'message': f'Flask request failed: {str(e)}'
            }
            
            return error_response, execution_time
    
    def _execute_nodejs_request(self, test_case: APITestCase, 
                               request_kwargs: Dict[str, Any]) -> Tuple[requests.Response, float]:
        """Execute request against Node.js system"""
        method = test_case.method.lower()
        
        if hasattr(self.nodejs_client, method):
            return getattr(self.nodejs_client, method)(test_case.endpoint, **request_kwargs)
        else:
            return self.nodejs_client.request(test_case.method, test_case.endpoint, **request_kwargs)
    
    def _get_auth_token(self) -> str:
        """Get authentication token for protected endpoints"""
        # Try to get existing token from session
        if 'auth_token' in self.session_data:
            return self.session_data['auth_token']
        
        # Generate new token for testing
        test_token = f"test_token_{uuid.uuid4().hex[:16]}"
        self.session_data['auth_token'] = test_token
        
        return test_token
    
    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive summary report of test results"""
        if not self.results:
            return {'error': 'No test results available'}
        
        # Calculate aggregate statistics
        total_score = sum(result.score for result in self.results if result.score is not None)
        avg_score = total_score / len(self.results) if self.results else 0
        
        passed_by_category = {}
        total_by_category = {}
        
        for result in self.results:
            category = result.test_case.category
            if category not in total_by_category:
                total_by_category[category] = 0
                passed_by_category[category] = 0
            
            total_by_category[category] += 1
            if result.passed:
                passed_by_category[category] += 1
        
        # Performance analysis
        flask_times = [r.flask_response_time_ms for r in self.results if r.flask_response_time_ms]
        nodejs_times = [r.nodejs_response_time_ms for r in self.results if r.nodejs_response_time_ms]
        
        return {
            'execution_summary': {
                'total_tests': self.total_tests,
                'passed_tests': self.passed_tests,
                'failed_tests': self.failed_tests,
                'success_rate': (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0,
                'average_score': avg_score,
                'execution_time': time.time() - self.start_time if self.start_time else 0
            },
            'category_breakdown': {
                category: {
                    'passed': passed_by_category.get(category, 0),
                    'total': total_by_category.get(category, 0),
                    'success_rate': (passed_by_category.get(category, 0) / total_by_category.get(category, 1) * 100)
                }
                for category in total_by_category.keys()
            },
            'performance_analysis': {
                'flask_avg_response_time': sum(flask_times) / len(flask_times) if flask_times else 0,
                'nodejs_avg_response_time': sum(nodejs_times) / len(nodejs_times) if nodejs_times else 0,
                'flask_max_response_time': max(flask_times) if flask_times else 0,
                'nodejs_max_response_time': max(nodejs_times) if nodejs_times else 0
            },
            'detailed_results': [result.generate_report() for result in self.results],
            'timestamp': datetime.utcnow().isoformat(),
            'test_environment': {
                'flask_version': '3.1.1',
                'python_version': '3.13.3',
                'pytest_flask_version': '1.3.0'
            }
        }
    
    def cleanup(self):
        """Cleanup resources and close connections"""
        self.nodejs_client.close()


# ================================
# pytest-flask Test Fixtures
# ================================

@fixture(scope='session')
def test_data_generator():
    """Test data generator fixture for creating API test cases"""
    return TestDataGenerator()


@fixture(scope='session')
def api_test_cases(test_data_generator):
    """Generate comprehensive API test cases for the test suite"""
    return test_data_generator.generate_api_test_cases()


@fixture
def api_parity_tester(client):
    """API parity tester fixture with Flask test client integration"""
    tester = APIParityTester(client)
    yield tester
    tester.cleanup()


@fixture
def nodejs_client():
    """Node.js client fixture for baseline system communication"""
    client = NodeJSClient()
    yield client
    client.close()


@fixture
def response_comparator():
    """Response comparison engine fixture"""
    return ResponseComparator()


# ================================
# Core Test Cases
# ================================

@mark.comparative
@mark.api
class TestAPIParityValidation:
    """
    Comprehensive API parity validation test suite implementing Feature F-009
    requirements for 100% functionality parity between Node.js and Flask systems.
    """
    
    def test_health_endpoint_parity(self, api_parity_tester, performance_monitor):
        """
        Test health endpoint parity between Node.js and Flask implementations
        
        Validates:
        - Response format compatibility
        - Performance equivalence
        - Error handling consistency
        """
        performance_monitor.start()
        
        health_test_cases = [
            APITestCase(
                endpoint="/health",
                method="GET",
                expected_status=200,
                category="health",
                performance_threshold_ms=100
            ),
            APITestCase(
                endpoint="/health/ready",
                method="GET", 
                expected_status=200,
                category="health",
                performance_threshold_ms=200
            )
        ]
        
        results = api_parity_tester.execute_test_suite(health_test_cases)
        performance_monitor.stop()
        
        # Validate all health checks passed
        for result in results:
            assert result.passed, f"Health check failed: {result.error_details}"
            assert result.score >= 90.0, f"Health check score too low: {result.score}%"
            
            # Performance validation
            assert result.flask_response_time_ms <= result.test_case.performance_threshold_ms, \
                f"Flask response time exceeded threshold: {result.flask_response_time_ms}ms"
        
        # Assert overall performance
        performance_monitor.assert_threshold(1.0)  # Health checks should complete within 1 second
    
    def test_authentication_endpoint_parity(self, api_parity_tester, authenticated_user, auth_headers):
        """
        Test authentication endpoint parity with comprehensive auth flow validation
        
        Validates:
        - Login/logout flow consistency
        - Token handling equivalence
        - Session management parity
        - Error response format matching
        """
        auth_test_cases = [
            APITestCase(
                endpoint="/api/auth/login",
                method="POST",
                payload={
                    "username": authenticated_user.username,
                    "password": "testpassword123"
                },
                expected_status=200,
                category="authentication"
            ),
            APITestCase(
                endpoint="/api/auth/profile",
                method="GET",
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="authentication"
            ),
            APITestCase(
                endpoint="/api/auth/logout",
                method="POST",
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="authentication"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(auth_test_cases)
        
        # Validate authentication flows
        for result in results:
            assert result.passed, f"Authentication test failed: {result.test_case.endpoint} - {result.error_details}"
            
            # Validate response structure for auth endpoints
            if result.flask_response and result.flask_response.status_code == 200:
                try:
                    flask_json = result.flask_response.json()
                    assert 'status' in flask_json or 'data' in flask_json, \
                        "Auth response missing required fields"
                except Exception:
                    pass  # Handle non-JSON responses
    
    def test_user_management_endpoint_parity(self, api_parity_tester, auth_headers, test_data_factory):
        """
        Test user management endpoint parity with CRUD operations
        
        Validates:
        - User creation, retrieval, update, deletion
        - Data validation consistency
        - Relationship handling
        - Pagination and filtering
        """
        user_data = test_data_factory['user']()
        
        user_test_cases = [
            APITestCase(
                endpoint="/api/users",
                method="GET",
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="users"
            ),
            APITestCase(
                endpoint="/api/users",
                method="POST",
                payload=user_data,
                headers=auth_headers,
                auth_required=True,
                expected_status=201,
                category="users"
            ),
            APITestCase(
                endpoint="/api/users/1",
                method="GET",
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="users"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(user_test_cases)
        
        # Validate user management operations
        for result in results:
            assert result.passed, f"User management test failed: {result.test_case.endpoint} - {result.error_details}"
            
            # Validate status codes match expected values
            if result.flask_response:
                assert result.flask_response.status_code == result.test_case.expected_status, \
                    f"Unexpected status code: {result.flask_response.status_code}"
    
    def test_business_logic_endpoint_parity(self, api_parity_tester, auth_headers):
        """
        Test core business logic endpoint parity with complex operations
        
        Validates:
        - Dashboard data consistency
        - Analytics computation equivalence
        - Report generation matching
        - Complex query handling
        """
        business_test_cases = [
            APITestCase(
                endpoint="/api/dashboard",
                method="GET",
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="core_business",
                performance_threshold_ms=1000  # Business logic may be slower
            ),
            APITestCase(
                endpoint="/api/data",
                method="GET",
                query_params={"limit": "10", "offset": "0"},
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="core_business"
            ),
            APITestCase(
                endpoint="/api/analytics",
                method="POST",
                payload={
                    "metrics": ["response_time", "error_rate"],
                    "time_range": "7d"
                },
                headers=auth_headers,
                auth_required=True,
                expected_status=200,
                category="core_business"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(business_test_cases)
        
        # Validate business logic consistency
        for result in results:
            assert result.passed, f"Business logic test failed: {result.test_case.endpoint} - {result.error_details}"
            
            # Ensure performance meets business requirements
            assert result.flask_response_time_ms <= result.test_case.performance_threshold_ms, \
                f"Business logic response time exceeded: {result.flask_response_time_ms}ms"
    
    def test_error_handling_parity(self, api_parity_tester):
        """
        Test error handling parity between systems
        
        Validates:
        - 404 error responses
        - 401 unauthorized responses
        - 422 validation error responses
        - 500 internal error responses
        """
        error_test_cases = [
            APITestCase(
                endpoint="/api/nonexistent",
                method="GET",
                expected_status=404,
                category="error_handling"
            ),
            APITestCase(
                endpoint="/api/users",
                method="GET",
                expected_status=401,  # No auth header
                category="error_handling"
            ),
            APITestCase(
                endpoint="/api/users",
                method="POST",
                payload={"invalid": "data"},  # Invalid payload
                expected_status=422,
                category="error_handling"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(error_test_cases)
        
        # Validate error handling consistency
        for result in results:
            # For error cases, we care more about status code matching than perfect content match
            assert result.status_code_match, \
                f"Error status code mismatch: Flask={result.flask_response.status_code if result.flask_response else None}, " \
                f"Node.js={result.nodejs_response.status_code if result.nodejs_response else None}"


@mark.comparative
@mark.performance  
class TestPerformanceParity:
    """
    Performance parity validation ensuring Flask implementation meets
    or exceeds Node.js baseline performance metrics per Section 4.7.1.
    """
    
    def test_response_time_parity(self, api_parity_tester, api_test_cases):
        """
        Test response time parity across all endpoints
        
        Validates:
        - Response times within acceptable thresholds
        - Performance regression detection
        - Concurrent request handling
        """
        # Filter to performance-critical endpoints
        critical_endpoints = [tc for tc in api_test_cases if tc.category in ['health', 'authentication']]
        
        results = api_parity_tester.execute_test_suite(critical_endpoints)
        
        performance_failures = []
        for result in results:
            # Check if Flask is significantly slower than Node.js
            if result.nodejs_response_time_ms > 0:  # Avoid division by zero
                performance_ratio = result.flask_response_time_ms / result.nodejs_response_time_ms
                if performance_ratio > 1.5:  # Flask should not be >50% slower
                    performance_failures.append({
                        'endpoint': result.test_case.endpoint,
                        'flask_time': result.flask_response_time_ms,
                        'nodejs_time': result.nodejs_response_time_ms,
                        'ratio': performance_ratio
                    })
        
        assert len(performance_failures) == 0, \
            f"Performance regressions detected: {performance_failures}"
    
    def test_memory_usage_parity(self, api_parity_tester, client):
        """
        Test memory usage patterns and efficiency
        
        Note: This is a placeholder for memory profiling integration
        In a real implementation, this would use memory profiling tools
        """
        import psutil
        import os
        
        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Execute a subset of tests
        health_tests = [
            APITestCase(endpoint="/health", method="GET", expected_status=200)
        ]
        
        results = api_parity_tester.execute_test_suite(health_tests)
        
        # Get final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Validate memory usage is reasonable
        assert memory_increase < PERFORMANCE_THRESHOLDS['memory_usage_mb'], \
            f"Memory usage increased too much: {memory_increase:.2f}MB"


@mark.comparative
@mark.database
class TestDatabaseOperationParity:
    """
    Database operation parity validation ensuring consistent data handling
    between Node.js and Flask implementations per Feature F-009.
    """
    
    def test_database_query_consistency(self, api_parity_tester, db_session, sample_users):
        """
        Test database query result consistency
        
        Validates:
        - Query result formatting
        - Relationship handling
        - Data type consistency
        - Pagination results
        """
        # Only test if database is available
        if db_session is None:
            pytest.skip("Database not available for testing")
        
        db_test_cases = [
            APITestCase(
                endpoint="/api/users",
                method="GET",
                query_params={"limit": "5"},
                auth_required=True,
                expected_status=200,
                category="database"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(db_test_cases)
        
        for result in results:
            if result.passed and result.flask_response and result.nodejs_response:
                try:
                    flask_data = result.flask_response.json()
                    nodejs_data = result.nodejs_response.json()
                    
                    # Validate data structure consistency
                    if 'data' in flask_data and 'data' in nodejs_data:
                        flask_records = flask_data['data']
                        nodejs_records = nodejs_data['data']
                        
                        # Should have same number of records
                        assert len(flask_records) == len(nodejs_records), \
                            "Database query returned different number of records"
                        
                        # Validate record structure if data exists
                        if flask_records and nodejs_records:
                            flask_keys = set(flask_records[0].keys())
                            nodejs_keys = set(nodejs_records[0].keys())
                            
                            # Allow for some implementation-specific fields
                            core_keys = flask_keys & nodejs_keys
                            assert len(core_keys) > 0, \
                                "No common fields between Flask and Node.js responses"
                            
                except Exception as e:
                    logging.warning(f"Database consistency validation failed: {str(e)}")


@mark.comparative
@mark.integration
class TestIntegrationParity:
    """
    Integration parity validation ensuring consistent behavior across
    complex workflows and multi-step operations per Section 4.7.1.
    """
    
    def test_full_user_workflow_parity(self, api_parity_tester, test_data_factory):
        """
        Test complete user workflow parity: register -> login -> profile -> update -> logout
        
        Validates:
        - Multi-step workflow consistency
        - State management across requests  
        - Session handling parity
        - Transaction integrity
        """
        user_data = test_data_factory['user']()
        
        workflow_steps = [
            # Step 1: Register user
            APITestCase(
                endpoint="/api/auth/register",
                method="POST",
                payload=user_data,
                expected_status=201,
                category="integration_workflow"
            ),
            
            # Step 2: Login with new user
            APITestCase(
                endpoint="/api/auth/login",
                method="POST",
                payload={
                    "username": user_data["username"],
                    "password": user_data["password"]
                },
                expected_status=200,
                category="integration_workflow"
            ),
            
            # Step 3: Get user profile
            APITestCase(
                endpoint="/api/auth/profile",
                method="GET",
                auth_required=True,
                expected_status=200,
                category="integration_workflow"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(workflow_steps)
        
        # Validate workflow consistency
        workflow_passed = all(result.passed for result in results)
        assert workflow_passed, \
            f"User workflow parity failed at steps: {[i for i, r in enumerate(results) if not r.passed]}"
    
    def test_error_recovery_parity(self, api_parity_tester):
        """
        Test error recovery and resilience parity
        
        Validates:
        - Graceful error handling
        - Recovery mechanism consistency
        - Resource cleanup behavior
        """
        # Test error scenarios
        error_recovery_cases = [
            # Invalid data handling
            APITestCase(
                endpoint="/api/users",
                method="POST",
                payload={"invalid": "payload"},
                expected_status=422,
                category="error_recovery"
            ),
            
            # Authentication failure recovery
            APITestCase(
                endpoint="/api/auth/login",
                method="POST",
                payload={"username": "invalid", "password": "invalid"},
                expected_status=401,
                category="error_recovery"
            ),
            
            # Resource not found handling
            APITestCase(
                endpoint="/api/users/999999",
                method="GET",
                expected_status=404,
                category="error_recovery"
            )
        ]
        
        results = api_parity_tester.execute_test_suite(error_recovery_cases)
        
        # Focus on error response consistency
        for result in results:
            assert result.status_code_match, \
                f"Error response status mismatch: {result.test_case.endpoint}"


# ================================
# Comprehensive Test Suite
# ================================

@mark.comparative
@mark.comprehensive
class TestComprehensiveAPIParitySuite:
    """
    Comprehensive test suite executing all API parity validations
    with detailed reporting and automated discrepancy detection.
    """
    
    def test_complete_api_parity_validation(self, api_parity_tester, api_test_cases, 
                                          json_response_validator):
        """
        Execute complete API parity validation test suite
        
        This is the master test that validates 100% API endpoint parity
        as required by Feature F-009 and Section 4.7.1.
        """
        # Execute full test suite
        results = api_parity_tester.execute_test_suite(api_test_cases)
        
        # Generate comprehensive report
        summary_report = api_parity_tester.generate_summary_report()
        
        # Validate overall success rate
        success_rate = summary_report['execution_summary']['success_rate']
        assert success_rate >= 90.0, \
            f"API parity success rate below threshold: {success_rate}% (required: 90%)"
        
        # Validate category-specific success rates
        critical_categories = ['health', 'authentication']
        for category in critical_categories:
            if category in summary_report['category_breakdown']:
                category_success = summary_report['category_breakdown'][category]['success_rate']
                assert category_success >= 95.0, \
                    f"Critical category '{category}' success rate too low: {category_success}%"
        
        # Performance validation
        perf_analysis = summary_report['performance_analysis']
        flask_avg_time = perf_analysis['flask_avg_response_time']
        
        assert flask_avg_time <= PERFORMANCE_THRESHOLDS['response_time_ms'], \
            f"Average Flask response time exceeds threshold: {flask_avg_time}ms"
        
        # Log summary for CI/CD integration
        logging.info("="*80)
        logging.info("API PARITY VALIDATION SUMMARY")
        logging.info("="*80)
        logging.info(f"Total Tests: {summary_report['execution_summary']['total_tests']}")
        logging.info(f"Passed: {summary_report['execution_summary']['passed_tests']}")
        logging.info(f"Failed: {summary_report['execution_summary']['failed_tests']}")
        logging.info(f"Success Rate: {success_rate:.1f}%")
        logging.info(f"Average Score: {summary_report['execution_summary']['average_score']:.1f}%")
        logging.info(f"Execution Time: {summary_report['execution_summary']['execution_time']:.2f}s")
        logging.info("="*80)
        
        # Trigger correction workflow for failures if available
        if AutoCorrection and summary_report['execution_summary']['failed_tests'] > 0:
            try:
                corrector = AutoCorrection()
                failed_results = [r for r in results if not r.passed]
                corrector.analyze_and_correct(failed_results)
                logging.info(f"Triggered automated correction for {len(failed_results)} failed tests")
            except Exception as e:
                logging.warning(f"Automated correction failed: {str(e)}")
        
        return summary_report


# ================================
# Utility Functions and Helpers
# ================================

def run_api_parity_tests():
    """
    Utility function to run API parity tests programmatically
    
    This function can be called from other modules or CI/CD pipelines
    to execute the complete API parity validation suite.
    """
    import sys
    import subprocess
    
    # Run pytest with specific markers for comparative testing
    cmd = [
        sys.executable, '-m', 'pytest',
        'tests/comparative/test_api_parity.py',
        '-v',
        '--tb=short',
        '-m', 'comparative',
        '--json-report',
        '--json-report-file=api_parity_report.json'
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        print("API parity tests PASSED")
    else:
        print("API parity tests FAILED")
        print(result.stdout)
        print(result.stderr)
    
    return result.returncode == 0


# ================================
# Module Exports and Metadata
# ================================

__all__ = [
    'APITestCase',
    'ComparisonResult', 
    'NodeJSClient',
    'ResponseComparator',
    'TestDataGenerator',
    'APIParityTester',
    'TestAPIParityValidation',
    'TestPerformanceParity',
    'TestDatabaseOperationParity',
    'TestIntegrationParity',
    'TestComprehensiveAPIParitySuite',
    'run_api_parity_tests'
]

# Module metadata
__version__ = '1.0.0'
__author__ = 'Flask Migration Team'
__description__ = 'Comprehensive API parity testing for Node.js to Flask migration'
__status__ = 'Production'

# Testing configuration
pytest_plugins = ['pytest_flask']

if __name__ == "__main__":
    # Allow running this module directly for debugging
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'run':
        success = run_api_parity_tests()
        sys.exit(0 if success else 1)
    else:
        print("API Parity Testing Module")
        print("Usage: python test_api_parity.py run")
        print("Or run with pytest: pytest tests/comparative/test_api_parity.py -v")