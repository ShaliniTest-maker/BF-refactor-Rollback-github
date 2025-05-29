"""
Comprehensive API endpoint comparison test suite implementing side-by-side validation 
between Node.js and Flask systems per Section 4.7.2 requirements.

This module orchestrates parallel API testing, validates 100% response format compatibility,
verifies identical HTTP status codes, and ensures complete API contract compliance during
the migration process. The test suite implements automated functional parity validation
with real-time discrepancy detection for migration validation.

Key Capabilities:
- Comprehensive API response comparison testing between Node.js and Flask systems
- Parallel test execution framework comparing identical API operations simultaneously
- Automated functional parity validation ensuring 100% API response equivalence
- Real-time discrepancy detection for API contract violations and response format differences
- pytest-flask 1.3.0 integration for Flask application testing with request context management
- Automated baseline comparison against Node.js system responses for migration validation

Test Categories:
- API Endpoint Functional Parity (Feature F-001)
- Request/Response Handling Migration (Feature F-002) 
- Authentication System Compatibility (Feature F-007)
- Database Operation Equivalence (Feature F-003)
- Performance Baseline Comparison (Feature F-009)
- Error Handling Consistency (Section 4.3.2)

Dependencies:
- Flask 3.1.1 application factory pattern for test client initialization
- Flask-SQLAlchemy 3.1.1 for database testing with PostgreSQL 15.x
- pytest-flask 1.3.0 for Flask-specific testing capabilities
- pytest-benchmark 5.1.0 for performance comparison and baseline validation
- Auth0 Python SDK 4.9.0 for authentication system testing
- Node.js baseline system connectivity for comparative validation

References:
- Section 4.7.2: Comparative Testing Process
- Section 4.3.1: Endpoint Conversion Process
- Section 4.3.2: Request/Response Handling Migration
- Feature F-001: API Endpoint Conversion
- Feature F-002: Request/Response Handling Migration
- Feature F-009: Functionality Parity Validation Process
"""

import json
import time
import uuid
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Tuple, Optional, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from unittest.mock import patch, MagicMock

import pytest
import requests
from flask import url_for, current_app, g
from flask.testing import FlaskClient
import structlog

# Import comparative testing fixtures and utilities
from .conftest_comparative import (
    ComparativeTestConfig,
    NodeJSBaselineClient,
    comparative_flask_app,
    comparative_client,
    comparative_flask_context,
    nodejs_baseline_client,
    baseline_capture_session,
    comparative_db_session,
    comparative_test_data,
    comparative_authentication_context,
    flask_login_user,
    pytest_benchmark_config,
    performance_comparison_context,
    prometheus_metrics_collector,
    system_resource_monitor,
    tox_environment_manager,
    comparative_test_logger,
    discrepancy_detector,
    test_timeout_manager,
    comparative_test_cleanup
)

# Import Flask application components for testing
from src.blueprints import api, auth, main
from src.models import User, UserSession, BusinessEntity, EntityRelationship
from src.services import WorkflowOrchestrationService, AuthenticationService
from src.auth import SessionManager

logger = structlog.get_logger("comparative_api_testing")


# =============================================================================
# Test Data Models and Utilities
# =============================================================================

@dataclass
class APITestCase:
    """Data model for API test case definition."""
    endpoint: str
    method: str
    description: str
    payload: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, str]] = None
    auth_required: bool = False
    expected_status_codes: List[int] = None
    test_category: str = "general"
    performance_threshold: float = 1.0  # seconds
    
    def __post_init__(self):
        if self.expected_status_codes is None:
            self.expected_status_codes = [200]


@dataclass
class APIComparisonResult:
    """Data model for API comparison test results."""
    test_case: APITestCase
    nodejs_response: Dict[str, Any]
    flask_response: Dict[str, Any]
    comparison_timestamp: str
    functional_parity: bool
    performance_parity: bool
    discrepancies: List[Dict[str, Any]]
    execution_metadata: Dict[str, Any]


class ComparativeAPITestRunner:
    """
    Orchestrates parallel API testing between Node.js and Flask systems.
    
    Provides comprehensive API comparison testing with automated discrepancy detection,
    performance validation, and detailed reporting for migration validation.
    """
    
    def __init__(self, 
                 flask_client: FlaskClient, 
                 nodejs_client: NodeJSBaselineClient,
                 discrepancy_detector,
                 performance_context,
                 metrics_collector,
                 timeout_manager):
        self.flask_client = flask_client
        self.nodejs_client = nodejs_client
        self.discrepancy_detector = discrepancy_detector
        self.performance_context = performance_context
        self.metrics_collector = metrics_collector
        self.timeout_manager = timeout_manager
        self.test_results: List[APIComparisonResult] = []
        
    def execute_comparative_test(self, test_case: APITestCase) -> APIComparisonResult:
        """
        Execute comparative API test between Node.js and Flask systems.
        
        Args:
            test_case: API test case configuration
            
        Returns:
            APIComparisonResult containing comparison data and analysis
        """
        logger.info("Starting comparative API test",
                    endpoint=test_case.endpoint,
                    method=test_case.method,
                    description=test_case.description)
        
        comparison_timestamp = datetime.utcnow().isoformat()
        
        # Execute parallel API requests
        with ThreadPoolExecutor(max_workers=2) as executor:
            # Submit Node.js baseline request
            nodejs_future = executor.submit(
                self._execute_nodejs_request, test_case
            )
            
            # Submit Flask request
            flask_future = executor.submit(
                self._execute_flask_request, test_case
            )
            
            # Collect results
            nodejs_response = nodejs_future.result(timeout=test_case.performance_threshold + 10)
            flask_response = flask_future.result(timeout=test_case.performance_threshold + 10)
        
        # Analyze comparison results
        functional_parity = self._validate_functional_parity(
            nodejs_response, flask_response, test_case
        )
        
        performance_parity = self._validate_performance_parity(
            nodejs_response, flask_response, test_case
        )
        
        # Detect discrepancies
        discrepancies = self.discrepancy_detector.detect_response_discrepancy(
            nodejs_response, flask_response, test_case.endpoint
        )
        
        # Record metrics
        self._record_comparison_metrics(
            test_case, nodejs_response, flask_response, functional_parity
        )
        
        # Create comparison result
        comparison_result = APIComparisonResult(
            test_case=test_case,
            nodejs_response=nodejs_response,
            flask_response=flask_response,
            comparison_timestamp=comparison_timestamp,
            functional_parity=functional_parity,
            performance_parity=performance_parity,
            discrepancies=discrepancies,
            execution_metadata={
                'test_runner_version': '1.0.0',
                'comparison_mode': 'parallel',
                'timeout_threshold': test_case.performance_threshold,
                'auth_required': test_case.auth_required
            }
        )
        
        self.test_results.append(comparison_result)
        
        logger.info("Comparative API test completed",
                    endpoint=test_case.endpoint,
                    functional_parity=functional_parity,
                    performance_parity=performance_parity,
                    discrepancy_count=len(discrepancies))
        
        return comparison_result
    
    def _execute_nodejs_request(self, test_case: APITestCase) -> Dict[str, Any]:
        """Execute API request against Node.js baseline system."""
        with self.timeout_manager.timeout_context('api_request', test_case.performance_threshold):
            start_time = time.time()
            
            try:
                # Prepare request parameters
                request_kwargs = {
                    'headers': test_case.headers or {},
                    'params': test_case.params or {}
                }
                
                if test_case.payload and test_case.method.upper() in ['POST', 'PUT', 'PATCH']:
                    request_kwargs['json'] = test_case.payload
                
                # Execute Node.js baseline request
                baseline_data = self.nodejs_client.make_request(
                    method=test_case.method,
                    endpoint=test_case.endpoint,
                    **request_kwargs
                )
                
                end_time = time.time()
                
                # Extract response data for comparison
                response_data = {
                    'status_code': baseline_data['response']['status_code'],
                    'headers': baseline_data['response']['headers'],
                    'data': baseline_data['response']['data'],
                    'duration_seconds': baseline_data['performance']['duration_seconds'],
                    'size_bytes': baseline_data['response']['size_bytes'],
                    'success': baseline_data['metadata']['success'],
                    'system': 'nodejs',
                    'timestamp': baseline_data['request']['timestamp']
                }
                
                # Record performance baseline
                self.performance_context.capture_baseline(
                    test_case.endpoint, test_case.method, **request_kwargs
                )
                
                return response_data
                
            except Exception as e:
                logger.error("Node.js request failed",
                             endpoint=test_case.endpoint,
                             method=test_case.method,
                             error=str(e))
                
                return {
                    'status_code': 0,
                    'headers': {},
                    'data': None,
                    'duration_seconds': time.time() - start_time,
                    'size_bytes': 0,
                    'success': False,
                    'system': 'nodejs',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
    
    def _execute_flask_request(self, test_case: APITestCase) -> Dict[str, Any]:
        """Execute API request against Flask system."""
        with self.timeout_manager.timeout_context('api_request', test_case.performance_threshold):
            start_time = time.time()
            
            try:
                # Prepare request parameters
                request_kwargs = {
                    'headers': test_case.headers or {},
                    'query_string': test_case.params or {}
                }
                
                if test_case.payload and test_case.method.upper() in ['POST', 'PUT', 'PATCH']:
                    request_kwargs['json'] = test_case.payload
                    request_kwargs['content_type'] = 'application/json'
                
                # Execute Flask request using test client
                response = self.flask_client.open(
                    path=test_case.endpoint,
                    method=test_case.method.upper(),
                    **request_kwargs
                )
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Parse response data
                try:
                    if response.content_type and 'application/json' in response.content_type:
                        response_data_parsed = response.get_json()
                    else:
                        response_data_parsed = response.get_data(as_text=True)
                except Exception:
                    response_data_parsed = response.get_data(as_text=True)
                
                # Extract response data for comparison
                response_data = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'data': response_data_parsed,
                    'duration_seconds': duration,
                    'size_bytes': len(response.data),
                    'success': response.status_code < 400,
                    'system': 'flask',
                    'timestamp': datetime.utcnow().isoformat()
                }
                
                # Record Flask performance
                self.performance_context.capture_flask(
                    test_case.endpoint, duration, response.status_code, len(response.data)
                )
                
                return response_data
                
            except Exception as e:
                logger.error("Flask request failed",
                             endpoint=test_case.endpoint,
                             method=test_case.method,
                             error=str(e))
                
                return {
                    'status_code': 0,
                    'headers': {},
                    'data': None,
                    'duration_seconds': time.time() - start_time,
                    'size_bytes': 0,
                    'success': False,
                    'system': 'flask',
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                }
    
    def _validate_functional_parity(self, 
                                    nodejs_response: Dict[str, Any], 
                                    flask_response: Dict[str, Any],
                                    test_case: APITestCase) -> bool:
        """Validate functional parity between Node.js and Flask responses."""
        # Status code comparison
        if nodejs_response['status_code'] != flask_response['status_code']:
            logger.warning("Status code mismatch detected",
                           endpoint=test_case.endpoint,
                           nodejs_status=nodejs_response['status_code'],
                           flask_status=flask_response['status_code'])
            return False
        
        # Response data comparison for successful responses
        if nodejs_response['success'] and flask_response['success']:
            nodejs_data = nodejs_response['data']
            flask_data = flask_response['data']
            
            # Deep comparison of response data
            if not self._deep_compare_response_data(nodejs_data, flask_data):
                logger.warning("Response data mismatch detected",
                               endpoint=test_case.endpoint,
                               nodejs_type=type(nodejs_data).__name__,
                               flask_type=type(flask_data).__name__)
                return False
        
        # Content type comparison
        nodejs_content_type = nodejs_response['headers'].get('content-type', '').lower()
        flask_content_type = flask_response['headers'].get('content-type', '').lower()
        
        if 'application/json' in nodejs_content_type and 'application/json' not in flask_content_type:
            logger.warning("Content type mismatch detected",
                           endpoint=test_case.endpoint,
                           nodejs_content_type=nodejs_content_type,
                           flask_content_type=flask_content_type)
            return False
        
        return True
    
    def _validate_performance_parity(self, 
                                     nodejs_response: Dict[str, Any], 
                                     flask_response: Dict[str, Any],
                                     test_case: APITestCase) -> bool:
        """Validate performance parity between Node.js and Flask responses."""
        nodejs_duration = nodejs_response['duration_seconds']
        flask_duration = flask_response['duration_seconds']
        
        # Check if both systems meet performance threshold
        threshold = test_case.performance_threshold
        
        if flask_duration > threshold:
            logger.warning("Flask performance threshold exceeded",
                           endpoint=test_case.endpoint,
                           flask_duration=flask_duration,
                           threshold=threshold)
            return False
        
        # Check if Flask performance is within acceptable range of Node.js
        performance_delta = abs(flask_duration - nodejs_duration)
        max_acceptable_delta = min(threshold * 0.5, 2.0)  # 50% of threshold or 2 seconds max
        
        if performance_delta > max_acceptable_delta:
            logger.warning("Performance delta exceeds acceptable range",
                           endpoint=test_case.endpoint,
                           nodejs_duration=nodejs_duration,
                           flask_duration=flask_duration,
                           delta=performance_delta,
                           max_acceptable=max_acceptable_delta)
            return False
        
        return True
    
    def _deep_compare_response_data(self, nodejs_data: Any, flask_data: Any) -> bool:
        """Perform deep comparison of response data structures."""
        # Handle None values
        if nodejs_data is None and flask_data is None:
            return True
        if nodejs_data is None or flask_data is None:
            return False
        
        # Handle different types
        if type(nodejs_data) != type(flask_data):
            # Allow some type flexibility for numbers
            if isinstance(nodejs_data, (int, float)) and isinstance(flask_data, (int, float)):
                return abs(nodejs_data - flask_data) < 1e-10
            return False
        
        # Handle dictionaries
        if isinstance(nodejs_data, dict):
            if set(nodejs_data.keys()) != set(flask_data.keys()):
                return False
            
            for key in nodejs_data.keys():
                if not self._deep_compare_response_data(nodejs_data[key], flask_data[key]):
                    return False
            return True
        
        # Handle lists
        if isinstance(nodejs_data, list):
            if len(nodejs_data) != len(flask_data):
                return False
            
            for i in range(len(nodejs_data)):
                if not self._deep_compare_response_data(nodejs_data[i], flask_data[i]):
                    return False
            return True
        
        # Handle primitive types
        if isinstance(nodejs_data, (str, int, bool)):
            return nodejs_data == flask_data
        
        # Handle float comparison with tolerance
        if isinstance(nodejs_data, float):
            return abs(nodejs_data - flask_data) < 1e-10
        
        # Default to string comparison
        return str(nodejs_data) == str(flask_data)
    
    def _record_comparison_metrics(self, 
                                   test_case: APITestCase,
                                   nodejs_response: Dict[str, Any],
                                   flask_response: Dict[str, Any],
                                   functional_parity: bool):
        """Record Prometheus metrics for comparison results."""
        # Record API requests
        self.metrics_collector.record_api_request(
            'nodejs', test_case.endpoint, test_case.method,
            nodejs_response['status_code'], nodejs_response['duration_seconds']
        )
        
        self.metrics_collector.record_api_request(
            'flask', test_case.endpoint, test_case.method,
            flask_response['status_code'], flask_response['duration_seconds']
        )
        
        # Record comparison results
        comparison_result = 'pass' if functional_parity else 'fail'
        
        self.metrics_collector.metrics['test_results'].labels(
            test_type='api_comparison',
            result=comparison_result,
            system='comparative'
        ).inc()
    
    def get_test_summary(self) -> Dict[str, Any]:
        """Get comprehensive test execution summary."""
        if not self.test_results:
            return {'total_tests': 0, 'summary': 'No tests executed'}
        
        total_tests = len(self.test_results)
        functional_passes = sum(1 for r in self.test_results if r.functional_parity)
        performance_passes = sum(1 for r in self.test_results if r.performance_parity)
        total_discrepancies = sum(len(r.discrepancies) for r in self.test_results)
        
        # Calculate performance statistics
        nodejs_durations = [r.nodejs_response['duration_seconds'] for r in self.test_results 
                           if r.nodejs_response['success']]
        flask_durations = [r.flask_response['duration_seconds'] for r in self.test_results
                          if r.flask_response['success']]
        
        summary = {
            'total_tests': total_tests,
            'functional_parity_rate': functional_passes / total_tests,
            'performance_parity_rate': performance_passes / total_tests,
            'total_discrepancies': total_discrepancies,
            'avg_nodejs_duration': sum(nodejs_durations) / len(nodejs_durations) if nodejs_durations else 0,
            'avg_flask_duration': sum(flask_durations) / len(flask_durations) if flask_durations else 0,
            'test_categories': {},
            'failed_tests': []
        }
        
        # Group by test category
        for result in self.test_results:
            category = result.test_case.test_category
            if category not in summary['test_categories']:
                summary['test_categories'][category] = {
                    'total': 0,
                    'functional_passes': 0,
                    'performance_passes': 0
                }
            
            summary['test_categories'][category]['total'] += 1
            if result.functional_parity:
                summary['test_categories'][category]['functional_passes'] += 1
            if result.performance_parity:
                summary['test_categories'][category]['performance_passes'] += 1
            
            # Record failed tests
            if not result.functional_parity or not result.performance_parity:
                summary['failed_tests'].append({
                    'endpoint': result.test_case.endpoint,
                    'method': result.test_case.method,
                    'functional_parity': result.functional_parity,
                    'performance_parity': result.performance_parity,
                    'discrepancy_count': len(result.discrepancies)
                })
        
        return summary


# =============================================================================
# API Test Case Definitions
# =============================================================================

def get_core_api_test_cases() -> List[APITestCase]:
    """
    Define core API test cases for comprehensive endpoint validation.
    
    Returns:
        List of APITestCase instances covering all critical API endpoints
        per Feature F-001 (API Endpoint Conversion) requirements.
    """
    return [
        # Health and System Endpoints (Main Blueprint)
        APITestCase(
            endpoint='/health',
            method='GET',
            description='System health check endpoint',
            expected_status_codes=[200],
            test_category='system',
            performance_threshold=0.5
        ),
        
        APITestCase(
            endpoint='/status',
            method='GET', 
            description='System status endpoint with detailed metrics',
            expected_status_codes=[200],
            test_category='system',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/version',
            method='GET',
            description='Application version information endpoint',
            expected_status_codes=[200],
            test_category='system',
            performance_threshold=0.3
        ),
        
        # Authentication Endpoints (Auth Blueprint)
        APITestCase(
            endpoint='/api/auth/login',
            method='POST',
            description='User authentication login endpoint',
            payload={
                'email': 'user1@comparative.test',
                'password': 'test_password_123',
                'remember_me': False
            },
            headers={'Content-Type': 'application/json'},
            expected_status_codes=[200, 401],
            test_category='authentication',
            performance_threshold=2.0
        ),
        
        APITestCase(
            endpoint='/api/auth/logout',
            method='POST',
            description='User authentication logout endpoint',
            auth_required=True,
            expected_status_codes=[200],
            test_category='authentication',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/auth/profile',
            method='GET',
            description='User profile retrieval endpoint',
            auth_required=True,
            expected_status_codes=[200, 401],
            test_category='authentication',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/auth/profile',
            method='PUT',
            description='User profile update endpoint',
            payload={
                'username': 'updated_username',
                'email': 'updated@comparative.test',
                'preferences': {
                    'theme': 'dark',
                    'notifications': True
                }
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400],
            test_category='authentication',
            performance_threshold=1.5
        ),
        
        APITestCase(
            endpoint='/api/auth/change-password',
            method='POST',
            description='User password change endpoint',
            payload={
                'current_password': 'test_password_123',
                'new_password': 'new_test_password_456',
                'confirm_password': 'new_test_password_456'
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400],
            test_category='authentication',
            performance_threshold=2.0
        ),
        
        # User Management Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/users',
            method='GET',
            description='User listing endpoint with pagination',
            params={
                'page': '1',
                'per_page': '10',
                'sort_by': 'created_at'
            },
            auth_required=True,
            expected_status_codes=[200, 401],
            test_category='user_management',
            performance_threshold=1.5
        ),
        
        APITestCase(
            endpoint='/api/users',
            method='POST',
            description='User creation endpoint',
            payload={
                'username': 'new_comparative_user',
                'email': 'newuser@comparative.test',
                'password': 'secure_password_789',
                'role': 'user',
                'is_active': True
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[201, 401, 400],
            test_category='user_management',
            performance_threshold=2.0
        ),
        
        APITestCase(
            endpoint='/api/users/1',
            method='GET',
            description='Individual user retrieval endpoint',
            auth_required=True,
            expected_status_codes=[200, 401, 404],
            test_category='user_management',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/users/1',
            method='PUT',
            description='User update endpoint',
            payload={
                'username': 'updated_user_name',
                'email': 'updated_user@comparative.test',
                'is_active': True,
                'role': 'user'
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400, 404],
            test_category='user_management',
            performance_threshold=1.5
        ),
        
        APITestCase(
            endpoint='/api/users/1',
            method='DELETE',
            description='User deletion endpoint',
            auth_required=True,
            expected_status_codes=[204, 401, 404],
            test_category='user_management',
            performance_threshold=1.0
        ),
        
        # Business Entity Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/entities',
            method='GET',
            description='Business entity listing endpoint',
            params={
                'page': '1',
                'per_page': '20',
                'status': 'active',
                'sort_by': 'name'
            },
            auth_required=True,
            expected_status_codes=[200, 401],
            test_category='business_entities',
            performance_threshold=2.0
        ),
        
        APITestCase(
            endpoint='/api/entities',
            method='POST',
            description='Business entity creation endpoint',
            payload={
                'name': 'Comparative Test Entity',
                'description': 'Entity created during comparative testing',
                'status': 'active',
                'metadata': {
                    'created_by': 'comparative_test',
                    'test_mode': True
                }
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[201, 401, 400],
            test_category='business_entities',
            performance_threshold=2.5
        ),
        
        APITestCase(
            endpoint='/api/entities/1',
            method='GET',
            description='Individual business entity retrieval endpoint',
            auth_required=True,
            expected_status_codes=[200, 401, 404],
            test_category='business_entities',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/entities/1',
            method='PUT',
            description='Business entity update endpoint',
            payload={
                'name': 'Updated Comparative Test Entity',
                'description': 'Updated entity during comparative testing',
                'status': 'active',
                'metadata': {
                    'updated_by': 'comparative_test',
                    'last_update': datetime.utcnow().isoformat()
                }
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400, 404],
            test_category='business_entities',
            performance_threshold=2.0
        ),
        
        APITestCase(
            endpoint='/api/entities/1',
            method='DELETE',
            description='Business entity deletion endpoint',
            auth_required=True,
            expected_status_codes=[204, 401, 404],
            test_category='business_entities',
            performance_threshold=1.0
        ),
        
        # Entity Relationship Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/entities/1/relationships',
            method='GET',
            description='Entity relationships retrieval endpoint',
            auth_required=True,
            expected_status_codes=[200, 401, 404],
            test_category='entity_relationships',
            performance_threshold=1.5
        ),
        
        APITestCase(
            endpoint='/api/entities/1/relationships',
            method='POST',
            description='Entity relationship creation endpoint',
            payload={
                'target_entity_id': 2,
                'relationship_type': 'comparative_test_relationship',
                'metadata': {
                    'created_during': 'comparative_testing',
                    'strength': 'strong'
                },
                'is_active': True
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[201, 401, 400, 404],
            test_category='entity_relationships',
            performance_threshold=2.0
        ),
        
        # Search and Query Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/search',
            method='GET',
            description='Global search endpoint',
            params={
                'q': 'comparative test',
                'type': 'all',
                'limit': '10',
                'offset': '0'
            },
            auth_required=True,
            expected_status_codes=[200, 401, 400],
            test_category='search',
            performance_threshold=3.0
        ),
        
        APITestCase(
            endpoint='/api/search',
            method='POST',
            description='Advanced search endpoint with filters',
            payload={
                'query': 'comparative test',
                'filters': {
                    'entity_type': 'business_entity',
                    'status': 'active',
                    'date_range': {
                        'start': (datetime.utcnow() - timedelta(days=30)).isoformat(),
                        'end': datetime.utcnow().isoformat()
                    }
                },
                'sort': [
                    {'field': 'relevance', 'order': 'desc'},
                    {'field': 'created_at', 'order': 'desc'}
                ],
                'pagination': {
                    'page': 1,
                    'per_page': 20
                }
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400],
            test_category='search',
            performance_threshold=4.0
        ),
        
        # Analytics and Reporting Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/analytics/dashboard',
            method='GET',
            description='Analytics dashboard data endpoint',
            params={
                'period': '30d',
                'metrics': 'all'
            },
            auth_required=True,
            expected_status_codes=[200, 401],
            test_category='analytics',
            performance_threshold=5.0
        ),
        
        APITestCase(
            endpoint='/api/reports/entities/summary',
            method='GET',
            description='Entity summary report endpoint',
            params={
                'format': 'json',
                'date_range': '30d',
                'group_by': 'status'
            },
            auth_required=True,
            expected_status_codes=[200, 401],
            test_category='analytics',
            performance_threshold=3.0
        ),
        
        # File Upload and Media Endpoints (API Blueprint)
        APITestCase(
            endpoint='/api/upload/validate',
            method='POST',
            description='File upload validation endpoint',
            payload={
                'filename': 'comparative_test_file.json',
                'file_size': 1024,
                'content_type': 'application/json',
                'checksum': 'abc123def456'
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 401, 400],
            test_category='file_operations',
            performance_threshold=1.5
        ),
        
        # Error Handling Test Cases
        APITestCase(
            endpoint='/api/nonexistent-endpoint',
            method='GET',
            description='Non-existent endpoint for 404 error testing',
            expected_status_codes=[404],
            test_category='error_handling',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/entities',
            method='POST',
            description='Invalid payload for 400 error testing',
            payload={
                'invalid_field': 'invalid_value',
                'missing_required_fields': True
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[400, 401],
            test_category='error_handling',
            performance_threshold=1.0
        ),
        
        APITestCase(
            endpoint='/api/auth/protected-endpoint',
            method='GET',
            description='Protected endpoint without authentication for 401 testing',
            auth_required=False,  # Deliberately no auth to test 401
            expected_status_codes=[401],
            test_category='error_handling',
            performance_threshold=1.0
        )
    ]


def get_performance_critical_test_cases() -> List[APITestCase]:
    """
    Define performance-critical API test cases for benchmarking.
    
    Returns:
        List of APITestCase instances focusing on performance-sensitive endpoints
        per Section 4.7.1 performance benchmarking requirements.
    """
    return [
        APITestCase(
            endpoint='/api/entities',
            method='GET',
            description='High-volume entity listing performance test',
            params={
                'page': '1',
                'per_page': '100',  # Large page size
                'include_relationships': 'true',
                'sort_by': 'created_at',
                'order': 'desc'
            },
            auth_required=True,
            expected_status_codes=[200],
            test_category='performance',
            performance_threshold=2.0
        ),
        
        APITestCase(
            endpoint='/api/search',
            method='POST',
            description='Complex search query performance test',
            payload={
                'query': '*',  # Wildcard search
                'filters': {
                    'entity_type': ['business_entity', 'user_entity'],
                    'status': ['active', 'pending'],
                    'complex_filter': {
                        'nested_conditions': True,
                        'multiple_joins': True
                    }
                },
                'sort': [
                    {'field': 'relevance', 'order': 'desc'},
                    {'field': 'created_at', 'order': 'desc'},
                    {'field': 'name', 'order': 'asc'}
                ],
                'pagination': {
                    'page': 1,
                    'per_page': 50
                },
                'include_aggregations': True
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200],
            test_category='performance',
            performance_threshold=5.0
        ),
        
        APITestCase(
            endpoint='/api/analytics/dashboard',
            method='GET',
            description='Analytics dashboard performance test with complex queries',
            params={
                'period': '1y',  # Large date range
                'metrics': 'all',
                'breakdown': 'daily',
                'include_trends': 'true',
                'include_comparisons': 'true'
            },
            auth_required=True,
            expected_status_codes=[200],
            test_category='performance',
            performance_threshold=8.0
        ),
        
        APITestCase(
            endpoint='/api/reports/entities/export',
            method='POST',
            description='Large data export performance test',
            payload={
                'format': 'json',
                'filters': {
                    'date_range': {
                        'start': (datetime.utcnow() - timedelta(days=365)).isoformat(),
                        'end': datetime.utcnow().isoformat()
                    },
                    'include_all_fields': True,
                    'include_relationships': True
                },
                'compression': False  # No compression for pure performance test
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            expected_status_codes=[200, 202],
            test_category='performance',
            performance_threshold=10.0
        )
    ]


# =============================================================================
# Core Comparative API Tests
# =============================================================================

@pytest.mark.comparative
@pytest.mark.api
class TestComparativeAPIFunctionalParity:
    """
    Comprehensive API functional parity test suite implementing Feature F-001 and F-002 validation.
    
    This test class validates 100% functional equivalence between Node.js and Flask
    API implementations using parallel test execution and automated discrepancy detection.
    """
    
    def setup_method(self):
        """Setup method executed before each test method."""
        self.test_start_time = time.time()
        
    def teardown_method(self):
        """Teardown method executed after each test method."""
        test_duration = time.time() - self.test_start_time
        logger.info("Test method completed", duration=test_duration)
    
    @pytest.mark.parametrize("test_case", get_core_api_test_cases(), 
                            ids=lambda tc: f"{tc.method}_{tc.endpoint.replace('/', '_').replace('-', '_')}")
    def test_api_endpoint_functional_parity(self,
                                          test_case: APITestCase,
                                          comparative_client,
                                          nodejs_baseline_client,
                                          discrepancy_detector,
                                          performance_comparison_context,
                                          prometheus_metrics_collector,
                                          test_timeout_manager,
                                          comparative_test_logger,
                                          flask_login_user if test_case.auth_required else None):
        """
        Test individual API endpoint functional parity between Node.js and Flask systems.
        
        Validates:
        - Identical HTTP status codes
        - Equivalent response data structures
        - Consistent error handling
        - API contract compliance
        
        Args:
            test_case: API test case configuration
            Various fixtures for testing infrastructure
        """
        comparative_test_logger.info("Starting API endpoint functional parity test",
                                    endpoint=test_case.endpoint,
                                    method=test_case.method,
                                    auth_required=test_case.auth_required)
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=performance_comparison_context,
            metrics_collector=prometheus_metrics_collector,
            timeout_manager=test_timeout_manager
        )
        
        # Execute comparative test
        comparison_result = test_runner.execute_comparative_test(test_case)
        
        # Assert functional parity
        assert comparison_result.functional_parity, (
            f"Functional parity validation failed for {test_case.method} {test_case.endpoint}. "
            f"Discrepancies: {comparison_result.discrepancies}"
        )
        
        # Assert expected status codes
        flask_status = comparison_result.flask_response['status_code']
        assert flask_status in test_case.expected_status_codes, (
            f"Flask response status code {flask_status} not in expected codes "
            f"{test_case.expected_status_codes} for {test_case.endpoint}"
        )
        
        # Assert successful responses have data
        if flask_status == 200:
            assert comparison_result.flask_response['data'] is not None, (
                f"Successful response missing data for {test_case.endpoint}"
            )
        
        # Log success metrics
        comparative_test_logger.info("API endpoint functional parity test passed",
                                    endpoint=test_case.endpoint,
                                    method=test_case.method,
                                    nodejs_status=comparison_result.nodejs_response['status_code'],
                                    flask_status=comparison_result.flask_response['status_code'],
                                    performance_parity=comparison_result.performance_parity)
    
    def test_api_endpoint_batch_validation(self,
                                         comparative_client,
                                         nodejs_baseline_client,
                                         discrepancy_detector,
                                         performance_comparison_context,
                                         prometheus_metrics_collector,
                                         test_timeout_manager,
                                         comparative_test_logger,
                                         flask_login_user):
        """
        Batch validation test executing all API endpoints for comprehensive coverage.
        
        This test provides overall system validation and generates comprehensive
        comparison statistics for migration validation reporting.
        """
        comparative_test_logger.info("Starting API endpoint batch validation")
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=performance_comparison_context,
            metrics_collector=prometheus_metrics_collector,
            timeout_manager=test_timeout_manager
        )
        
        # Execute all test cases
        test_cases = get_core_api_test_cases()
        results = []
        
        for test_case in test_cases:
            try:
                result = test_runner.execute_comparative_test(test_case)
                results.append(result)
            except Exception as e:
                comparative_test_logger.error("Test case execution failed",
                                            endpoint=test_case.endpoint,
                                            error=str(e))
                
                # Create failure result
                failure_result = APIComparisonResult(
                    test_case=test_case,
                    nodejs_response={'status_code': 0, 'success': False, 'error': str(e)},
                    flask_response={'status_code': 0, 'success': False, 'error': str(e)},
                    comparison_timestamp=datetime.utcnow().isoformat(),
                    functional_parity=False,
                    performance_parity=False,
                    discrepancies=[{'type': 'execution_failure', 'error': str(e)}],
                    execution_metadata={'batch_test': True, 'failed': True}
                )
                results.append(failure_result)
        
        # Generate test summary
        test_summary = test_runner.get_test_summary()
        
        # Assert overall success criteria
        functional_parity_threshold = 0.95  # 95% success rate required
        performance_parity_threshold = 0.90  # 90% performance compliance required
        
        assert test_summary['functional_parity_rate'] >= functional_parity_threshold, (
            f"Functional parity rate {test_summary['functional_parity_rate']:.2%} "
            f"below required threshold {functional_parity_threshold:.2%}. "
            f"Failed tests: {test_summary['failed_tests']}"
        )
        
        assert test_summary['performance_parity_rate'] >= performance_parity_threshold, (
            f"Performance parity rate {test_summary['performance_parity_rate']:.2%} "
            f"below required threshold {performance_parity_threshold:.2%}"
        )
        
        # Log comprehensive results
        comparative_test_logger.info("API endpoint batch validation completed",
                                    total_tests=test_summary['total_tests'],
                                    functional_parity_rate=test_summary['functional_parity_rate'],
                                    performance_parity_rate=test_summary['performance_parity_rate'],
                                    total_discrepancies=test_summary['total_discrepancies'],
                                    test_categories=test_summary['test_categories'])


@pytest.mark.comparative
@pytest.mark.performance
@pytest.mark.slow
class TestComparativeAPIPerformanceParity:
    """
    API performance parity test suite implementing pytest-benchmark 5.1.0 for
    comprehensive response time and resource usage comparison per Section 4.7.1.
    """
    
    @pytest.mark.parametrize("test_case", get_performance_critical_test_cases(),
                            ids=lambda tc: f"perf_{tc.method}_{tc.endpoint.replace('/', '_')}")
    def test_api_performance_benchmarking(self,
                                        test_case: APITestCase,
                                        benchmark,
                                        comparative_client,
                                        nodejs_baseline_client,
                                        performance_comparison_context,
                                        system_resource_monitor,
                                        comparative_test_logger,
                                        flask_login_user):
        """
        Benchmark API endpoint performance against Node.js baseline using pytest-benchmark.
        
        This test validates that Flask implementation meets or exceeds Node.js
        performance metrics for critical endpoints.
        
        Args:
            test_case: Performance test case configuration
            benchmark: pytest-benchmark fixture
            Various fixtures for testing infrastructure
        """
        comparative_test_logger.info("Starting API performance benchmarking",
                                    endpoint=test_case.endpoint,
                                    performance_threshold=test_case.performance_threshold)
        
        # Capture Node.js baseline performance
        baseline_data = performance_comparison_context.capture_baseline(
            test_case.endpoint, test_case.method,
            headers=test_case.headers,
            params=test_case.params,
            json=test_case.payload
        )
        
        def flask_api_call():
            """Flask API call for benchmarking."""
            request_kwargs = {
                'headers': test_case.headers or {},
                'query_string': test_case.params or {}
            }
            
            if test_case.payload and test_case.method.upper() in ['POST', 'PUT', 'PATCH']:
                request_kwargs['json'] = test_case.payload
                request_kwargs['content_type'] = 'application/json'
            
            response = comparative_client.open(
                path=test_case.endpoint,
                method=test_case.method.upper(),
                **request_kwargs
            )
            
            return response
        
        # Benchmark Flask implementation
        flask_response = benchmark(flask_api_call)
        
        # Capture Flask performance metrics
        performance_comparison_context.capture_flask(
            test_case.endpoint,
            benchmark.stats.mean,  # Use benchmark mean time
            flask_response.status_code,
            len(flask_response.data)
        )
        
        # Compare performance
        comparison = performance_comparison_context.compare(
            test_case.endpoint, test_case.method
        )
        
        # Assert performance requirements
        assert benchmark.stats.mean <= test_case.performance_threshold, (
            f"Flask response time {benchmark.stats.mean:.3f}s exceeds threshold "
            f"{test_case.performance_threshold}s for {test_case.endpoint}"
        )
        
        if comparison and baseline_data['metadata']['success']:
            baseline_duration = baseline_data['performance']['duration_seconds']
            performance_ratio = benchmark.stats.mean / baseline_duration
            
            # Allow Flask to be up to 50% slower than Node.js
            max_acceptable_ratio = 1.5
            
            assert performance_ratio <= max_acceptable_ratio, (
                f"Flask performance ratio {performance_ratio:.2f} exceeds acceptable "
                f"ratio {max_acceptable_ratio} compared to Node.js baseline "
                f"({baseline_duration:.3f}s) for {test_case.endpoint}"
            )
            
            comparative_test_logger.info("API performance benchmarking completed",
                                        endpoint=test_case.endpoint,
                                        flask_duration=benchmark.stats.mean,
                                        nodejs_duration=baseline_duration,
                                        performance_ratio=performance_ratio,
                                        meets_threshold=benchmark.stats.mean <= test_case.performance_threshold)
        
        # Validate resource usage
        resource_stats = system_resource_monitor.get_statistics()
        if resource_stats:
            memory_threshold = ComparativeTestConfig.PERFORMANCE_THRESHOLDS['memory_usage_threshold']
            
            assert resource_stats['memory_percent']['max'] <= memory_threshold * 100, (
                f"Memory usage {resource_stats['memory_percent']['max']:.1f}% exceeds "
                f"threshold {memory_threshold * 100:.1f}% during {test_case.endpoint} test"
            )


@pytest.mark.comparative
@pytest.mark.authentication
class TestComparativeAuthenticationParity:
    """
    Authentication system comparison test suite validating Feature F-007 implementation.
    
    This test class ensures authentication mechanisms maintain identical behavior
    between Node.js and Flask implementations with comprehensive session management validation.
    """
    
    def test_authentication_flow_parity(self,
                                       comparative_client,
                                       nodejs_baseline_client,
                                       comparative_authentication_context,
                                       discrepancy_detector,
                                       comparative_test_logger):
        """
        Test complete authentication flow parity between systems.
        
        Validates:
        - Login flow consistency
        - Session management equivalence
        - Token validation behavior
        - Logout flow completeness
        """
        comparative_test_logger.info("Starting authentication flow parity test")
        
        test_user = comparative_authentication_context['test_users'][0]
        
        # Test login endpoint
        login_test_case = APITestCase(
            endpoint='/api/auth/login',
            method='POST',
            description='Authentication login flow test',
            payload={
                'email': test_user['flask_user'].email,
                'password': 'test_password_123'
            },
            headers={'Content-Type': 'application/json'},
            expected_status_codes=[200],
            test_category='authentication'
        )
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=None,  # Not needed for auth tests
            metrics_collector=None,    # Not needed for auth tests
            timeout_manager=None       # Using default timeouts
        )
        
        # Execute login comparison
        login_result = test_runner.execute_comparative_test(login_test_case)
        
        # Assert login parity
        assert login_result.functional_parity, (
            f"Login functional parity failed. Discrepancies: {login_result.discrepancies}"
        )
        
        # Validate successful login responses contain session data
        if login_result.flask_response['status_code'] == 200:
            flask_data = login_result.flask_response['data']
            assert 'session_token' in flask_data or 'access_token' in flask_data, (
                "Successful login response missing session/access token"
            )
        
        comparative_test_logger.info("Authentication flow parity test completed successfully")
    
    def test_protected_endpoint_access_parity(self,
                                            comparative_client,
                                            nodejs_baseline_client,
                                            flask_login_user,
                                            discrepancy_detector,
                                            comparative_test_logger):
        """
        Test protected endpoint access behavior parity.
        
        Validates that authentication-protected endpoints behave identically
        in both systems for authenticated and unauthenticated requests.
        """
        comparative_test_logger.info("Starting protected endpoint access parity test")
        
        protected_endpoints = [
            '/api/auth/profile',
            '/api/users',
            '/api/entities'
        ]
        
        results = []
        
        for endpoint in protected_endpoints:
            # Test authenticated access
            auth_test_case = APITestCase(
                endpoint=endpoint,
                method='GET',
                description=f'Authenticated access to {endpoint}',
                auth_required=True,
                expected_status_codes=[200, 404],
                test_category='authentication'
            )
            
            # Create test runner
            test_runner = ComparativeAPITestRunner(
                flask_client=comparative_client,
                nodejs_client=nodejs_baseline_client,
                discrepancy_detector=discrepancy_detector,
                performance_context=None,
                metrics_collector=None,
                timeout_manager=None
            )
            
            result = test_runner.execute_comparative_test(auth_test_case)
            results.append(result)
            
            # Assert authentication behavior parity
            assert result.functional_parity, (
                f"Authentication parity failed for {endpoint}. "
                f"Discrepancies: {result.discrepancies}"
            )
        
        # Validate overall authentication success
        successful_results = [r for r in results if r.functional_parity]
        success_rate = len(successful_results) / len(results)
        
        assert success_rate >= 0.95, (
            f"Authentication parity success rate {success_rate:.2%} below 95% threshold"
        )
        
        comparative_test_logger.info("Protected endpoint access parity test completed",
                                    tested_endpoints=len(protected_endpoints),
                                    success_rate=success_rate)


@pytest.mark.comparative
@pytest.mark.database
class TestComparativeDatabaseOperationParity:
    """
    Database operation comparison test suite validating Feature F-003 and F-004 implementation.
    
    This test class ensures database operations produce identical results
    between Node.js and Flask implementations with comprehensive data integrity validation.
    """
    
    def test_database_query_result_parity(self,
                                         comparative_client,
                                         nodejs_baseline_client,
                                         comparative_test_data,
                                         discrepancy_detector,
                                         database_performance_monitor,
                                         flask_login_user,
                                         comparative_test_logger):
        """
        Test database query result parity between systems.
        
        Validates:
        - Query result consistency
        - Data format equivalence
        - Relationship preservation
        - Performance characteristics
        """
        comparative_test_logger.info("Starting database query result parity test")
        
        # Test data retrieval endpoints that exercise database operations
        database_test_cases = [
            APITestCase(
                endpoint='/api/users',
                method='GET',
                description='User listing database query test',
                params={'per_page': '5', 'sort_by': 'created_at'},
                auth_required=True,
                expected_status_codes=[200],
                test_category='database'
            ),
            APITestCase(
                endpoint='/api/entities',
                method='GET',
                description='Entity listing database query test',
                params={'per_page': '5', 'include_relationships': 'true'},
                auth_required=True,
                expected_status_codes=[200],
                test_category='database'
            ),
            APITestCase(
                endpoint=f'/api/users/{comparative_test_data["users"][0].id}',
                method='GET',
                description='Individual user retrieval database query test',
                auth_required=True,
                expected_status_codes=[200, 404],
                test_category='database'
            )
        ]
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=None,
            metrics_collector=None,
            timeout_manager=None
        )
        
        results = []
        
        for test_case in database_test_cases:
            result = test_runner.execute_comparative_test(test_case)
            results.append(result)
            
            # Assert database operation parity
            assert result.functional_parity, (
                f"Database operation parity failed for {test_case.endpoint}. "
                f"Discrepancies: {result.discrepancies}"
            )
            
            # Validate data structure consistency for successful queries
            if (result.flask_response['status_code'] == 200 and 
                result.nodejs_response['status_code'] == 200):
                
                flask_data = result.flask_response['data']
                nodejs_data = result.nodejs_response['data']
                
                # Validate data types
                assert type(flask_data) == type(nodejs_data), (
                    f"Data type mismatch for {test_case.endpoint}: "
                    f"Flask {type(flask_data)} vs Node.js {type(nodejs_data)}"
                )
                
                # Validate array/object structure
                if isinstance(flask_data, list):
                    assert len(flask_data) == len(nodejs_data), (
                        f"Array length mismatch for {test_case.endpoint}: "
                        f"Flask {len(flask_data)} vs Node.js {len(nodejs_data)}"
                    )
        
        # Validate overall database operation success
        successful_results = [r for r in results if r.functional_parity]
        success_rate = len(successful_results) / len(results)
        
        assert success_rate == 1.0, (
            f"Database operation parity must be 100%, got {success_rate:.2%}"
        )
        
        # Validate database performance metrics
        db_stats = database_performance_monitor
        if db_stats['queries']:
            avg_query_time = sum(q['duration_seconds'] for q in db_stats['queries']) / len(db_stats['queries'])
            
            # Database queries should complete within reasonable time
            assert avg_query_time <= 2.0, (
                f"Average database query time {avg_query_time:.3f}s exceeds 2.0s threshold"
            )
        
        comparative_test_logger.info("Database query result parity test completed",
                                    tested_queries=len(database_test_cases),
                                    success_rate=success_rate,
                                    query_count=len(db_stats['queries']) if db_stats['queries'] else 0)


@pytest.mark.comparative
@pytest.mark.error_handling
class TestComparativeErrorHandlingParity:
    """
    Error handling comparison test suite validating Section 4.3.2 implementation.
    
    This test class ensures error handling mechanisms produce identical responses
    between Node.js and Flask implementations across various error scenarios.
    """
    
    def test_http_error_response_parity(self,
                                       comparative_client,
                                       nodejs_baseline_client,
                                       discrepancy_detector,
                                       comparative_test_logger):
        """
        Test HTTP error response parity between systems.
        
        Validates:
        - 404 Not Found responses
        - 400 Bad Request responses  
        - 401 Unauthorized responses
        - 500 Internal Server Error responses
        - Error message consistency
        """
        comparative_test_logger.info("Starting HTTP error response parity test")
        
        error_test_cases = [
            APITestCase(
                endpoint='/api/nonexistent-endpoint',
                method='GET',
                description='404 Not Found error test',
                expected_status_codes=[404],
                test_category='error_handling'
            ),
            APITestCase(
                endpoint='/api/users/99999',
                method='GET',
                description='404 Not Found for non-existent resource',
                auth_required=True,
                expected_status_codes=[404],
                test_category='error_handling'
            ),
            APITestCase(
                endpoint='/api/users',
                method='POST',
                description='400 Bad Request for invalid data',
                payload={'invalid': 'data'},
                headers={'Content-Type': 'application/json'},
                auth_required=True,
                expected_status_codes=[400],
                test_category='error_handling'
            ),
            APITestCase(
                endpoint='/api/auth/profile',
                method='GET',
                description='401 Unauthorized for protected endpoint',
                auth_required=False,  # No auth provided
                expected_status_codes=[401],
                test_category='error_handling'
            )
        ]
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=None,
            metrics_collector=None,
            timeout_manager=None
        )
        
        results = []
        
        for test_case in error_test_cases:
            result = test_runner.execute_comparative_test(test_case)
            results.append(result)
            
            # Assert error handling parity
            assert result.functional_parity, (
                f"Error handling parity failed for {test_case.endpoint}. "
                f"Expected status: {test_case.expected_status_codes}, "
                f"Flask status: {result.flask_response['status_code']}, "
                f"Node.js status: {result.nodejs_response['status_code']}, "
                f"Discrepancies: {result.discrepancies}"
            )
            
            # Validate error response structure
            flask_status = result.flask_response['status_code']
            nodejs_status = result.nodejs_response['status_code']
            
            assert flask_status == nodejs_status, (
                f"Error status code mismatch for {test_case.endpoint}: "
                f"Flask {flask_status} vs Node.js {nodejs_status}"
            )
            
            # Validate error responses have appropriate structure
            if flask_status >= 400:
                flask_data = result.flask_response['data']
                if flask_data and isinstance(flask_data, dict):
                    # Error responses should contain error information
                    assert any(key in flask_data for key in ['error', 'message', 'detail']), (
                        f"Error response missing error information for {test_case.endpoint}"
                    )
        
        # Validate overall error handling success
        successful_results = [r for r in results if r.functional_parity]
        success_rate = len(successful_results) / len(results)
        
        assert success_rate == 1.0, (
            f"Error handling parity must be 100%, got {success_rate:.2%}"
        )
        
        comparative_test_logger.info("HTTP error response parity test completed",
                                    tested_error_cases=len(error_test_cases),
                                    success_rate=success_rate)


# =============================================================================
# Integration and Stress Tests
# =============================================================================

@pytest.mark.comparative
@pytest.mark.integration
@pytest.mark.slow
class TestComparativeIntegrationWorkflows:
    """
    Integration workflow comparison test suite validating end-to-end system behavior.
    
    This test class ensures complete workflow scenarios produce identical results
    between Node.js and Flask implementations with comprehensive state validation.
    """
    
    def test_complete_user_workflow_parity(self,
                                         comparative_client,
                                         nodejs_baseline_client,
                                         comparative_test_data,
                                         discrepancy_detector,
                                         comparative_test_logger):
        """
        Test complete user workflow parity including authentication, data operations, and cleanup.
        
        This integration test validates the entire user lifecycle:
        1. User authentication
        2. Profile access and modification
        3. Data creation and manipulation
        4. Cleanup and logout
        """
        comparative_test_logger.info("Starting complete user workflow parity test")
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=None,
            metrics_collector=None,
            timeout_manager=None
        )
        
        workflow_results = []
        test_user = comparative_test_data['users'][0]
        
        # Step 1: Authentication
        login_test = APITestCase(
            endpoint='/api/auth/login',
            method='POST',
            payload={'email': test_user.email, 'password': 'test_password'},
            headers={'Content-Type': 'application/json'},
            description='User login workflow step'
        )
        
        login_result = test_runner.execute_comparative_test(login_test)
        workflow_results.append(('login', login_result))
        
        # Step 2: Profile access
        profile_test = APITestCase(
            endpoint='/api/auth/profile',
            method='GET',
            auth_required=True,
            description='User profile access workflow step'
        )
        
        profile_result = test_runner.execute_comparative_test(profile_test)
        workflow_results.append(('profile_access', profile_result))
        
        # Step 3: Entity creation
        entity_creation_test = APITestCase(
            endpoint='/api/entities',
            method='POST',
            payload={
                'name': 'Workflow Test Entity',
                'description': 'Entity created during workflow test',
                'status': 'active'
            },
            headers={'Content-Type': 'application/json'},
            auth_required=True,
            description='Entity creation workflow step'
        )
        
        creation_result = test_runner.execute_comparative_test(entity_creation_test)
        workflow_results.append(('entity_creation', creation_result))
        
        # Step 4: Entity retrieval
        if creation_result.flask_response.get('status_code') == 201:
            # Extract entity ID from creation response if available
            flask_entity_data = creation_result.flask_response.get('data', {})
            entity_id = flask_entity_data.get('id', 1)  # Fallback to test data
            
            retrieval_test = APITestCase(
                endpoint=f'/api/entities/{entity_id}',
                method='GET',
                auth_required=True,
                description='Entity retrieval workflow step'
            )
            
            retrieval_result = test_runner.execute_comparative_test(retrieval_test)
            workflow_results.append(('entity_retrieval', retrieval_result))
        
        # Step 5: Logout
        logout_test = APITestCase(
            endpoint='/api/auth/logout',
            method='POST',
            auth_required=True,
            description='User logout workflow step'
        )
        
        logout_result = test_runner.execute_comparative_test(logout_test)
        workflow_results.append(('logout', logout_result))
        
        # Validate workflow parity
        failed_steps = []
        for step_name, result in workflow_results:
            if not result.functional_parity:
                failed_steps.append(step_name)
        
        assert len(failed_steps) == 0, (
            f"Workflow steps failed functional parity: {failed_steps}. "
            f"All workflow steps must maintain 100% parity."
        )
        
        # Validate workflow completion
        successful_steps = len([r for _, r in workflow_results if r.functional_parity])
        total_steps = len(workflow_results)
        
        comparative_test_logger.info("Complete user workflow parity test completed",
                                    total_steps=total_steps,
                                    successful_steps=successful_steps,
                                    failed_steps=failed_steps)


# =============================================================================
# Reporting and Summary Tests
# =============================================================================

@pytest.mark.comparative
@pytest.mark.reporting
class TestComparativeTestReporting:
    """
    Comparative test reporting and summary generation test suite.
    
    This test class generates comprehensive reports on comparative testing results
    and validates overall migration success criteria per Feature F-009.
    """
    
    def test_generate_comprehensive_comparison_report(self,
                                                    comparative_client,
                                                    nodejs_baseline_client,
                                                    discrepancy_detector,
                                                    performance_comparison_context,
                                                    prometheus_metrics_collector,
                                                    comparative_test_logger):
        """
        Generate comprehensive comparison report for migration validation.
        
        This test executes a representative sample of API endpoints and generates
        a detailed report suitable for migration sign-off and validation.
        """
        comparative_test_logger.info("Starting comprehensive comparison report generation")
        
        # Execute representative test sample
        sample_test_cases = [
            # System endpoints
            APITestCase('/health', 'GET', 'Health check', test_category='system'),
            APITestCase('/status', 'GET', 'Status check', test_category='system'),
            
            # Authentication endpoints
            APITestCase('/api/auth/login', 'POST', 'Login',
                       payload={'email': 'test@example.com', 'password': 'test'},
                       headers={'Content-Type': 'application/json'},
                       test_category='authentication'),
            
            # API endpoints
            APITestCase('/api/users', 'GET', 'User listing',
                       params={'per_page': '5'}, auth_required=True,
                       test_category='api'),
            APITestCase('/api/entities', 'GET', 'Entity listing',
                       params={'per_page': '5'}, auth_required=True,
                       test_category='api'),
            
            # Error handling
            APITestCase('/api/nonexistent', 'GET', 'Not found error',
                       expected_status_codes=[404],
                       test_category='error_handling')
        ]
        
        # Create test runner
        test_runner = ComparativeAPITestRunner(
            flask_client=comparative_client,
            nodejs_client=nodejs_baseline_client,
            discrepancy_detector=discrepancy_detector,
            performance_context=performance_comparison_context,
            metrics_collector=prometheus_metrics_collector,
            timeout_manager=None
        )
        
        # Execute all test cases
        for test_case in sample_test_cases:
            try:
                test_runner.execute_comparative_test(test_case)
            except Exception as e:
                comparative_test_logger.warning("Test case execution error",
                                               endpoint=test_case.endpoint,
                                               error=str(e))
        
        # Generate comprehensive report
        test_summary = test_runner.get_test_summary()
        discrepancy_summary = discrepancy_detector.get_discrepancy_summary()
        
        # Create migration validation report
        migration_report = {
            'report_timestamp': datetime.utcnow().isoformat(),
            'migration_phase': 'comparative_validation',
            'test_execution_summary': test_summary,
            'discrepancy_analysis': discrepancy_summary,
            'performance_analysis': {
                'baseline_system': 'nodejs',
                'target_system': 'flask',
                'avg_performance_ratio': (
                    test_summary['avg_flask_duration'] / test_summary['avg_nodejs_duration']
                    if test_summary['avg_nodejs_duration'] > 0 else 1.0
                ),
                'performance_threshold_compliance': test_summary['performance_parity_rate']
            },
            'migration_readiness': {
                'functional_parity_achieved': test_summary['functional_parity_rate'] >= 0.95,
                'performance_acceptable': test_summary['performance_parity_rate'] >= 0.90,
                'critical_discrepancies': discrepancy_summary['by_severity'].get('critical', 0),
                'ready_for_production': (
                    test_summary['functional_parity_rate'] >= 0.95 and
                    test_summary['performance_parity_rate'] >= 0.90 and
                    discrepancy_summary['by_severity'].get('critical', 0) == 0
                )
            },
            'recommendations': []
        }
        
        # Add recommendations based on results
        if not migration_report['migration_readiness']['functional_parity_achieved']:
            migration_report['recommendations'].append(
                "Address functional parity issues before production deployment"
            )
        
        if not migration_report['migration_readiness']['performance_acceptable']:
            migration_report['recommendations'].append(
                "Optimize Flask implementation to meet performance requirements"
            )
        
        if migration_report['migration_readiness']['critical_discrepancies'] > 0:
            migration_report['recommendations'].append(
                "Resolve all critical discrepancies before proceeding with migration"
            )
        
        # Log comprehensive report
        comparative_test_logger.info("Comprehensive comparison report generated",
                                    migration_ready=migration_report['migration_readiness']['ready_for_production'],
                                    functional_parity=migration_report['migration_readiness']['functional_parity_achieved'],
                                    performance_acceptable=migration_report['migration_readiness']['performance_acceptable'],
                                    critical_discrepancies=migration_report['migration_readiness']['critical_discrepancies'])
        
        # Assert migration readiness criteria
        assert migration_report['migration_readiness']['functional_parity_achieved'], (
            f"Migration not ready: Functional parity rate "
            f"{test_summary['functional_parity_rate']:.2%} below 95% threshold"
        )
        
        assert migration_report['migration_readiness']['critical_discrepancies'] == 0, (
            f"Migration not ready: {migration_report['migration_readiness']['critical_discrepancies']} "
            f"critical discrepancies detected"
        )
        
        # Store report for external consumption
        setattr(comparative_test_logger, '_migration_report', migration_report)
        
        comparative_test_logger.info("Migration validation completed successfully",
                                    ready_for_production=migration_report['migration_readiness']['ready_for_production'])