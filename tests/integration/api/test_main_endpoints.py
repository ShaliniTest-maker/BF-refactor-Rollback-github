"""
Main Application Blueprint Integration Test Suite

This module provides comprehensive integration testing for the main application blueprint,
validating health check endpoints, system monitoring routes, and core application functionality
converted from Express.js route handlers. The test suite ensures proper health monitoring
capabilities, system status endpoints, and error handling mechanisms are functioning correctly
in the Flask environment for production deployment readiness.

Test Coverage:
- Main application route conversion maintaining system functionality per Feature F-001
- Health check and monitoring endpoint implementation per Section 8.5 requirements
- Flask error handling testing with @app.errorhandler decorators per Section 4.3.2
- Production monitoring endpoint validation for system health per Section 5.1.4
- Node.js middleware pattern testing conversion to Flask request processing per Feature F-002
- System status and observability endpoint testing per Section 8.5

Technical Requirements:
- pytest-flask 1.3.0 for Flask application testing fixtures per Section 4.7.1
- Flask blueprint testing using application factory pattern
- Health check endpoint validation for container orchestration per Section 6.5.2.1
- Prometheus metrics collection validation per Section 6.5.1.1
- Error response standardization testing per Section 4.3.2
- Performance and reliability validation for production deployment

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

import pytest
import json
import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from unittest.mock import patch, MagicMock

from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import Client

# Test markers for organization
pytestmark = [
    pytest.mark.integration,
    pytest.mark.api,
    pytest.mark.blueprint
]


class TestMainEndpointsBasicFunctionality:
    """
    Test class for basic main blueprint endpoint functionality.
    
    Validates core endpoint behavior, response formats, and basic
    functionality conversion from Express.js route handlers per Feature F-001.
    """
    
    def test_index_route_basic_functionality(self, client: FlaskClient) -> None:
        """
        Test index route basic functionality and response structure.
        
        Validates the main index route provides proper application information
        and maintains system functionality per Feature F-001 requirements.
        """
        # Act
        response = client.get('/')
        
        # Assert
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert 'success' in data
        assert data['success'] is True
        assert 'data' in data
        assert 'message' in data
        assert 'correlation_id' in data
        
        # Validate application information structure
        app_info = data['data']
        assert 'application' in app_info
        assert 'description' in app_info
        assert 'version' in app_info
        assert 'environment' in app_info
        assert 'python_version' in app_info
        assert 'platform' in app_info
        assert 'timestamp' in app_info
        assert 'blueprint' in app_info
        assert 'migration_status' in app_info
        
        # Validate specific values
        assert app_info['application'] == 'Flask Application'
        assert app_info['blueprint'] == 'main'
        assert app_info['migration_status'] == 'active'
        assert 'Python 3.13.3/Flask 3.1.1 migration' in app_info['description']
    
    def test_index_route_headers_and_security(self, client: FlaskClient) -> None:
        """
        Test index route security headers and response formatting.
        
        Validates security header implementation per Section 6.4.3.4
        and proper response time tracking.
        """
        # Act
        response = client.get('/')
        
        # Assert security headers
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        assert 'X-XSS-Protection' in response.headers
        assert response.headers['X-XSS-Protection'] == '1; mode=block'
        assert 'Referrer-Policy' in response.headers
        assert response.headers['Referrer-Policy'] == 'strict-origin-when-cross-origin'
        
        # Assert response time header
        assert 'X-Response-Time' in response.headers
        response_time = response.headers['X-Response-Time']
        assert response_time.endswith('s')
        assert float(response_time[:-1]) > 0  # Should be positive
        
        # Assert correlation ID header
        assert 'X-Correlation-ID' in response.headers
        correlation_id = response.headers['X-Correlation-ID']
        assert len(correlation_id) > 0
    
    def test_index_route_correlation_id_consistency(self, client: FlaskClient) -> None:
        """
        Test correlation ID consistency between response body and headers.
        
        Validates that correlation IDs are properly generated and consistent
        across response components for monitoring and debugging.
        """
        # Act
        response = client.get('/')
        
        # Assert
        data = response.get_json()
        header_correlation_id = response.headers.get('X-Correlation-ID')
        body_correlation_id = data.get('correlation_id')
        
        assert header_correlation_id is not None
        assert body_correlation_id is not None
        assert header_correlation_id == body_correlation_id
    
    def test_version_endpoint_functionality(self, client: FlaskClient) -> None:
        """
        Test application version endpoint functionality.
        
        Validates version information endpoint provides comprehensive
        version details for deployment verification.
        """
        # Act
        response = client.get('/version')
        
        # Assert
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is True
        
        version_info = data['data']
        assert 'application_version' in version_info
        assert 'framework_versions' in version_info
        assert 'build_info' in version_info
        assert 'migration_info' in version_info
        assert 'timestamp' in version_info
        
        # Validate framework versions
        framework_versions = version_info['framework_versions']
        assert 'flask' in framework_versions
        assert 'python' in framework_versions
        assert 'werkzeug' in framework_versions
        assert 'sqlalchemy' in framework_versions
        
        # Validate migration information
        migration_info = version_info['migration_info']
        assert migration_info['migration_status'] == 'completed'
        assert migration_info['source_technology'] == 'Node.js/Express.js'
        assert migration_info['target_technology'] == 'Python 3.13.3/Flask 3.1.1'
    
    def test_system_status_endpoint_functionality(self, client: FlaskClient) -> None:
        """
        Test system status endpoint for production monitoring.
        
        Validates system status endpoint per Section 5.1.4 for monitoring
        and observability in production environments.
        """
        # Act
        response = client.get('/status')
        
        # Assert
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is True
        
        status_data = data['data']
        assert 'application' in status_data
        assert 'system' in status_data
        assert 'configuration' in status_data
        assert 'blueprints' in status_data
        assert 'timestamp' in status_data
        
        # Validate application information
        app_info = status_data['application']
        assert app_info['name'] == 'Flask Application'
        assert app_info['migration_status'] == 'active'
        assert app_info['framework'].startswith('Flask')
        
        # Validate configuration status
        config_info = status_data['configuration']
        assert 'database_configured' in config_info
        assert config_info['monitoring_enabled'] is True
        assert config_info['health_checks_enabled'] is True
        assert config_info['metrics_enabled'] is True
        
        # Validate blueprint information
        blueprint_info = status_data['blueprints']
        assert 'registered_count' in blueprint_info
        assert 'blueprints' in blueprint_info
        assert isinstance(blueprint_info['blueprints'], list)
        assert 'main' in blueprint_info['blueprints']


class TestHealthCheckEndpoints:
    """
    Test class for health check endpoint functionality.
    
    Validates health check endpoints per Section 6.5.2.1 for container
    orchestration and production monitoring requirements.
    """
    
    def test_liveness_probe_basic_functionality(self, client: FlaskClient) -> None:
        """
        Test liveness probe endpoint basic functionality.
        
        Validates liveness probe for Kubernetes/ECS liveness probe per
        Section 6.5.2.1 with <50ms response time requirement.
        """
        # Act
        start_time = time.time()
        response = client.get('/health')
        end_time = time.time()
        
        # Assert response timing
        response_time = end_time - start_time
        assert response_time < 0.05  # Less than 50ms requirement
        
        # Assert response structure
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is True
        assert 'data' in data
        
        health_data = data['data']
        assert health_data['status'] == 'healthy'
        assert health_data['check_type'] == 'liveness'
        assert 'timestamp' in health_data
        assert 'response_time_seconds' in health_data
        assert 'application_version' in health_data
        assert 'python_version' in health_data
    
    def test_liveness_probe_alternative_endpoint(self, client: FlaskClient) -> None:
        """
        Test liveness probe alternative endpoint (/health/liveness).
        
        Validates that both /health and /health/liveness endpoints
        provide identical liveness probe functionality.
        """
        # Act
        response1 = client.get('/health')
        response2 = client.get('/health/liveness')
        
        # Assert both endpoints work
        assert response1.status_code == 200
        assert response2.status_code == 200
        
        data1 = response1.get_json()
        data2 = response2.get_json()
        
        # Assert same check type
        assert data1['data']['check_type'] == 'liveness'
        assert data2['data']['check_type'] == 'liveness'
        assert data1['data']['status'] == data2['data']['status']
    
    @patch('src.utils.monitoring.get_application_health')
    @patch('src.utils.monitoring.get_database_health')
    @patch('src.utils.monitoring.check_external_dependencies')
    def test_readiness_probe_comprehensive_checks(
        self,
        mock_deps_check: MagicMock,
        mock_db_health: MagicMock,
        mock_app_health: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test readiness probe comprehensive system checks.
        
        Validates readiness probe performs comprehensive system validation
        per Section 6.5.2.1 within 100ms requirement.
        """
        # Arrange
        mock_app_health.return_value = {'healthy': True, 'details': 'Application healthy'}
        mock_db_health.return_value = {'connected': True, 'details': 'Database connected'}
        mock_deps_check.return_value = {'all_healthy': True, 'details': 'All dependencies healthy'}
        
        # Act
        start_time = time.time()
        response = client.get('/health/readiness')
        end_time = time.time()
        
        # Assert response timing
        response_time = end_time - start_time
        assert response_time < 0.1  # Less than 100ms requirement
        
        # Assert response structure
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is True
        
        health_data = data['data']
        assert health_data['status'] == 'healthy'
        assert health_data['check_type'] == 'readiness'
        assert 'checks' in health_data
        
        # Validate individual checks
        checks = health_data['checks']
        assert 'application' in checks
        assert 'database' in checks
        assert 'external_dependencies' in checks
        
        assert checks['application']['status'] == 'healthy'
        assert checks['database']['status'] == 'healthy'
        assert checks['external_dependencies']['status'] == 'healthy'
        
        # Verify mocks were called
        mock_app_health.assert_called_once()
        mock_db_health.assert_called_once()
        mock_deps_check.assert_called_once()
    
    @patch('src.utils.monitoring.get_application_health')
    @patch('src.utils.monitoring.get_database_health')
    @patch('src.utils.monitoring.check_external_dependencies')
    def test_readiness_probe_degraded_state(
        self,
        mock_deps_check: MagicMock,
        mock_db_health: MagicMock,
        mock_app_health: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test readiness probe handling of degraded system state.
        
        Validates readiness probe properly reports degraded state when
        external dependencies are unhealthy but core system is functional.
        """
        # Arrange
        mock_app_health.return_value = {'healthy': True, 'details': 'Application healthy'}
        mock_db_health.return_value = {'connected': True, 'details': 'Database connected'}
        mock_deps_check.return_value = {'all_healthy': False, 'details': 'External dependency issue'}
        
        # Act
        response = client.get('/health/readiness')
        
        # Assert
        assert response.status_code == 200  # Still returns 200 for degraded state
        
        data = response.get_json()
        health_data = data['data']
        assert health_data['status'] == 'degraded'
        
        checks = health_data['checks']
        assert checks['application']['status'] == 'healthy'
        assert checks['database']['status'] == 'healthy'
        assert checks['external_dependencies']['status'] == 'degraded'
    
    @patch('src.utils.monitoring.get_application_health')
    @patch('src.utils.monitoring.get_database_health')
    def test_readiness_probe_unhealthy_state(
        self,
        mock_db_health: MagicMock,
        mock_app_health: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test readiness probe handling of unhealthy system state.
        
        Validates readiness probe returns 503 status when core
        system components are unhealthy.
        """
        # Arrange
        mock_app_health.return_value = {'healthy': True, 'details': 'Application healthy'}
        mock_db_health.return_value = {'connected': False, 'details': 'Database connection failed'}
        
        # Act
        response = client.get('/health/readiness')
        
        # Assert
        assert response.status_code == 503  # Service Unavailable for unhealthy state
        
        data = response.get_json()
        health_data = data['data']
        assert health_data['status'] == 'unhealthy'
        
        checks = health_data['checks']
        assert checks['application']['status'] == 'healthy'
        assert checks['database']['status'] == 'unhealthy'
    
    @patch('src.utils.monitoring.get_application_health')
    @patch('src.utils.monitoring.get_database_health')
    @patch('src.utils.monitoring.check_external_dependencies')
    @patch('src.utils.monitoring.get_system_metrics')
    def test_detailed_health_check_comprehensive(
        self,
        mock_system_metrics: MagicMock,
        mock_deps_check: MagicMock,
        mock_db_health: MagicMock,
        mock_app_health: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test detailed health check comprehensive system information.
        
        Validates detailed health endpoint provides comprehensive system
        status for administrative monitoring per Section 6.5.2.1.
        """
        # Arrange
        mock_app_health.return_value = {'healthy': True, 'details': 'Application healthy'}
        mock_db_health.return_value = {'connected': True, 'details': 'Database connected'}
        mock_deps_check.return_value = {'all_healthy': True, 'details': 'All dependencies healthy'}
        mock_system_metrics.return_value = {'cpu_usage': 25.5, 'memory_usage': 512}
        
        # Act
        start_time = time.time()
        response = client.get('/health/detailed')
        end_time = time.time()
        
        # Assert response timing
        response_time = end_time - start_time
        assert response_time < 0.2  # Less than 200ms requirement
        
        # Assert response structure
        assert response.status_code == 200
        assert response.is_json
        
        data = response.get_json()
        health_data = data['data']
        
        assert health_data['overall_status'] == 'healthy'
        assert health_data['check_type'] == 'detailed'
        assert 'components' in health_data
        assert 'summary' in health_data
        assert 'uptime_seconds' in health_data
        
        # Validate component details
        components = health_data['components']
        assert 'application' in components
        assert 'system' in components
        assert 'database' in components
        assert 'external_dependencies' in components
        
        # Validate application component details
        app_component = components['application']
        assert 'version' in app_component
        assert 'environment' in app_component
        assert 'blueprint_count' in app_component
        assert 'registered_blueprints' in app_component
        
        # Validate system component details
        system_component = components['system']
        assert 'python_version' in system_component
        assert 'platform' in system_component
        assert 'memory_usage' in system_component
        assert 'cpu_usage' in system_component
        assert 'disk_usage' in system_component
        
        # Validate summary statistics
        summary = health_data['summary']
        assert 'total_components' in summary
        assert 'healthy_components' in summary
        assert summary['total_components'] > 0
        assert summary['healthy_components'] > 0


class TestPrometheusMetricsEndpoint:
    """
    Test class for Prometheus metrics endpoint functionality.
    
    Validates metrics endpoint per Section 6.5.1.1 for monitoring
    infrastructure integration and observability.
    """
    
    @patch('src.utils.monitoring.get_prometheus_metrics')
    def test_prometheus_metrics_endpoint_basic(
        self,
        mock_get_metrics: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test Prometheus metrics endpoint basic functionality.
        
        Validates metrics endpoint returns proper Prometheus format
        per Section 6.5.1.1 requirements.
        """
        # Arrange
        mock_metrics = """# HELP flask_requests_total Total requests
# TYPE flask_requests_total counter
flask_requests_total{method="GET",status="200"} 100
"""
        mock_get_metrics.return_value = mock_metrics
        
        # Act
        response = client.get('/metrics')
        
        # Assert
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/plain; version=0.0.4; charset=utf-8'
        assert 'X-Correlation-ID' in response.headers
        
        # Validate metrics content
        metrics_text = response.get_data(as_text=True)
        assert 'flask_requests_total' in metrics_text
        assert 'flask_main_blueprint_requests_total' in metrics_text
        assert 'flask_main_blueprint_health_checks_total' in metrics_text
        assert 'flask_application_info' in metrics_text
        
        # Verify mock was called
        mock_get_metrics.assert_called_once()
    
    @patch('src.utils.monitoring.get_prometheus_metrics')
    def test_prometheus_metrics_custom_metrics(
        self,
        mock_get_metrics: MagicMock,
        client: FlaskClient,
        app: Flask
    ) -> None:
        """
        Test Prometheus metrics custom application metrics.
        
        Validates custom metrics are properly included in the metrics
        output for main blueprint monitoring.
        """
        # Arrange
        mock_get_metrics.return_value = "# Base metrics\n"
        
        # Set some custom metric values
        with app.app_context():
            app._main_bp_request_count = 42
            app._liveness_check_count = 10
            app._readiness_check_count = 5
            app._detailed_check_count = 2
        
        # Act
        response = client.get('/metrics')
        
        # Assert
        metrics_text = response.get_data(as_text=True)
        
        # Validate custom metrics are present
        assert 'flask_main_blueprint_requests_total{blueprint="main",version="1.0.0"} 42' in metrics_text
        assert 'flask_main_blueprint_health_checks_total{check_type="liveness"} 10' in metrics_text
        assert 'flask_main_blueprint_health_checks_total{check_type="readiness"} 5' in metrics_text
        assert 'flask_main_blueprint_health_checks_total{check_type="detailed"} 2' in metrics_text
        assert 'flask_application_info' in metrics_text
    
    @patch('src.utils.monitoring.get_prometheus_metrics', side_effect=Exception('Metrics error'))
    def test_prometheus_metrics_error_handling(
        self,
        mock_get_metrics: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test Prometheus metrics endpoint error handling.
        
        Validates metrics endpoint gracefully handles errors and
        returns appropriate error response.
        """
        # Act
        response = client.get('/metrics')
        
        # Assert
        assert response.status_code == 500
        assert response.headers['Content-Type'] == 'text/plain'
        
        metrics_text = response.get_data(as_text=True)
        assert metrics_text == "# Error generating metrics\n"


class TestErrorHandling:
    """
    Test class for Flask error handling functionality.
    
    Validates Flask @app.errorhandler decorators provide standardized
    error responses per Section 4.3.2 requirements.
    """
    
    def test_404_error_handling(self, client: FlaskClient) -> None:
        """
        Test 404 Not Found error handling for main blueprint.
        
        Validates 404 error handler provides standardized error response
        format per Section 4.3.2 requirements.
        """
        # Act
        response = client.get('/nonexistent-endpoint')
        
        # Assert
        assert response.status_code == 404
        assert response.is_json
        
        data = response.get_json()
        assert 'success' in data
        assert data['success'] is False
        assert 'error' in data
        assert 'error_code' in data
        assert 'correlation_id' in data
        
        error_info = data['error']
        assert 'message' in error_info
        assert 'status_code' in error_info
        assert 'details' in error_info
        
        assert error_info['status_code'] == 404
        assert data['error_code'] == 'RESOURCE_NOT_FOUND'
        assert 'not found' in error_info['message'].lower()
        
        # Validate error details
        details = error_info['details']
        assert 'path' in details
        assert 'method' in details
        assert 'blueprint' in details
        assert details['path'] == '/nonexistent-endpoint'
        assert details['method'] == 'GET'
        assert details['blueprint'] == 'main'
    
    @patch('src.blueprints.main.get_application_health', side_effect=Exception('Test error'))
    def test_500_error_handling(
        self,
        mock_health: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test 500 Internal Server Error handling for main blueprint.
        
        Validates 500 error handler provides secure error response
        without exposing sensitive information per Section 4.3.2.
        """
        # Act
        response = client.get('/health/readiness')
        
        # Assert
        assert response.status_code == 500
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is False
        assert 'error' in data
        assert 'error_code' in data
        assert 'correlation_id' in data
        
        error_info = data['error']
        assert error_info['status_code'] == 500
        assert data['error_code'] == 'INTERNAL_SERVER_ERROR'
        
        # Validate error message is generic (not exposing internal details)
        assert 'internal server error' in error_info['message'].lower()
        assert 'Test error' not in error_info['message']  # Internal error details hidden
    
    @patch('src.blueprints.main.create_correlation_id', side_effect=ValueError('Correlation error'))
    def test_general_exception_handling(
        self,
        mock_correlation: MagicMock,
        client: FlaskClient
    ) -> None:
        """
        Test general exception handling for main blueprint.
        
        Validates catch-all exception handler provides consistent
        error response format for unexpected errors.
        """
        # Act
        response = client.get('/')
        
        # Assert
        assert response.status_code == 500
        assert response.is_json
        
        data = response.get_json()
        assert data['success'] is False
        assert data['error_code'] == 'UNEXPECTED_ERROR'
        
        error_info = data['error']
        assert 'unexpected error' in error_info['message'].lower()
        assert 'blueprint' in error_info['details']
        assert 'error_type' in error_info['details']
        assert 'timestamp' in error_info['details']
    
    def test_error_response_security_headers(self, client: FlaskClient) -> None:
        """
        Test error responses include security headers.
        
        Validates error responses maintain security header
        requirements even during error conditions.
        """
        # Act
        response = client.get('/nonexistent-endpoint')
        
        # Assert
        assert response.status_code == 404
        
        # Validate security headers are present
        assert 'X-Content-Type-Options' in response.headers
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in response.headers
        assert response.headers['X-Frame-Options'] == 'DENY'
        assert 'X-XSS-Protection' in response.headers
        assert 'Referrer-Policy' in response.headers
    
    def test_error_response_correlation_id_consistency(self, client: FlaskClient) -> None:
        """
        Test error response correlation ID consistency.
        
        Validates error responses maintain correlation ID consistency
        between headers and response body for debugging.
        """
        # Act
        response = client.get('/nonexistent-endpoint')
        
        # Assert
        data = response.get_json()
        header_correlation_id = response.headers.get('X-Correlation-ID')
        body_correlation_id = data.get('correlation_id')
        
        assert header_correlation_id is not None
        assert body_correlation_id is not None
        assert header_correlation_id == body_correlation_id


class TestRequestResponseProcessing:
    """
    Test class for request/response processing functionality.
    
    Validates Flask request processing mechanisms converted from
    Node.js middleware patterns per Feature F-002.
    """
    
    def test_before_request_processing(self, client: FlaskClient) -> None:
        """
        Test before_request handler functionality.
        
        Validates before_request handler properly processes requests
        and generates correlation IDs per Section 4.3.2.
        """
        # Act
        response = client.get('/')
        
        # Assert
        assert response.status_code == 200
        
        # Validate correlation ID is generated and consistent
        data = response.get_json()
        correlation_id = data.get('correlation_id')
        assert correlation_id is not None
        assert len(correlation_id) > 0
        
        # Validate correlation ID in headers
        header_correlation_id = response.headers.get('X-Correlation-ID')
        assert header_correlation_id == correlation_id
    
    def test_after_request_processing(self, client: FlaskClient) -> None:
        """
        Test after_request handler functionality.
        
        Validates after_request handler adds proper headers and
        response processing per Section 4.3.2.
        """
        # Act
        response = client.get('/')
        
        # Assert response time header
        assert 'X-Response-Time' in response.headers
        response_time = response.headers['X-Response-Time']
        assert response_time.endswith('s')
        
        # Parse and validate response time
        time_value = float(response_time[:-1])
        assert time_value > 0
        assert time_value < 1.0  # Should be subsecond for simple request
    
    def test_request_size_validation(self, client: FlaskClient) -> None:
        """
        Test request size validation in before_request handler.
        
        Validates request size limits are enforced for security
        per before_request handler implementation.
        """
        # Create large request data (> 1MB)
        large_data = 'x' * (1024 * 1024 + 1)  # 1MB + 1 byte
        
        # Act
        response = client.post(
            '/',
            data=large_data,
            content_type='text/plain'
        )
        
        # Assert
        assert response.status_code == 413  # Request Entity Too Large
        
        data = response.get_json()
        assert data['success'] is False
        assert 'too large' in data['error']['message'].lower()
    
    def test_request_method_support(self, client: FlaskClient) -> None:
        """
        Test HTTP method support for main endpoints.
        
        Validates proper HTTP method handling and response
        for supported and unsupported methods.
        """
        # Test supported GET method
        response = client.get('/')
        assert response.status_code == 200
        
        # Test unsupported POST method on index
        response = client.post('/')
        assert response.status_code == 405  # Method Not Allowed
        
        # Test unsupported PUT method
        response = client.put('/')
        assert response.status_code == 405
        
        # Test unsupported DELETE method
        response = client.delete('/')
        assert response.status_code == 405


class TestPerformanceRequirements:
    """
    Test class for performance requirement validation.
    
    Validates main blueprint endpoints meet performance requirements
    per Section 2.1.9 and production deployment standards.
    """
    
    @pytest.mark.performance
    def test_liveness_probe_response_time(self, client: FlaskClient) -> None:
        """
        Test liveness probe response time requirement.
        
        Validates liveness probe meets <50ms response time requirement
        per Section 6.5.2.1 for container orchestration.
        """
        # Test multiple requests to ensure consistent performance
        response_times = []
        
        for _ in range(10):
            start_time = time.time()
            response = client.get('/health')
            end_time = time.time()
            
            assert response.status_code == 200
            response_time = end_time - start_time
            response_times.append(response_time)
        
        # Validate all response times are under 50ms
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        assert avg_response_time < 0.05  # 50ms average
        assert max_response_time < 0.1   # 100ms maximum
    
    @pytest.mark.performance
    def test_readiness_probe_response_time(self, client: FlaskClient) -> None:
        """
        Test readiness probe response time requirement.
        
        Validates readiness probe meets <100ms response time requirement
        per Section 6.5.2.1 for container orchestration.
        """
        # Test multiple requests
        response_times = []
        
        for _ in range(5):
            start_time = time.time()
            response = client.get('/health/readiness')
            end_time = time.time()
            
            assert response.status_code in [200, 503]  # Healthy or unhealthy
            response_time = end_time - start_time
            response_times.append(response_time)
        
        # Validate response time requirements
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        
        assert avg_response_time < 0.1   # 100ms average
        assert max_response_time < 0.2   # 200ms maximum
    
    @pytest.mark.performance
    def test_detailed_health_response_time(self, client: FlaskClient) -> None:
        """
        Test detailed health check response time requirement.
        
        Validates detailed health check meets <200ms response time
        requirement per Section 6.5.2.1.
        """
        # Act
        start_time = time.time()
        response = client.get('/health/detailed')
        end_time = time.time()
        
        # Assert
        assert response.status_code == 200
        response_time = end_time - start_time
        assert response_time < 0.2  # 200ms requirement
    
    @pytest.mark.performance
    def test_index_route_performance(self, client: FlaskClient) -> None:
        """
        Test index route performance consistency.
        
        Validates index route maintains consistent performance
        for production deployment reliability.
        """
        # Test multiple requests for consistency
        response_times = []
        
        for _ in range(20):
            start_time = time.time()
            response = client.get('/')
            end_time = time.time()
            
            assert response.status_code == 200
            response_time = end_time - start_time
            response_times.append(response_time)
        
        # Validate performance consistency
        avg_response_time = sum(response_times) / len(response_times)
        max_response_time = max(response_times)
        min_response_time = min(response_times)
        
        # Basic performance requirements
        assert avg_response_time < 0.1    # 100ms average
        assert max_response_time < 0.2    # 200ms maximum
        
        # Consistency check (max should not be more than 10x min)
        assert max_response_time / min_response_time < 10


class TestProductionReadiness:
    """
    Test class for production deployment readiness validation.
    
    Validates main blueprint endpoints are ready for production
    deployment per Section 8.1 requirements.
    """
    
    def test_all_endpoints_accessibility(self, client: FlaskClient) -> None:
        """
        Test all main blueprint endpoints are accessible.
        
        Validates all defined endpoints respond correctly and
        are ready for production deployment.
        """
        endpoints = [
            ('GET', '/'),
            ('GET', '/health'),
            ('GET', '/health/liveness'),
            ('GET', '/health/readiness'),
            ('GET', '/health/detailed'),
            ('GET', '/metrics'),
            ('GET', '/status'),
            ('GET', '/version')
        ]
        
        for method, endpoint in endpoints:
            if method == 'GET':
                response = client.get(endpoint)
            else:
                continue  # Only testing GET endpoints in main blueprint
            
            # All endpoints should return successful responses
            assert response.status_code in [200, 503], f"Endpoint {endpoint} failed with {response.status_code}"
            
            # All endpoints should return JSON (except metrics)
            if endpoint != '/metrics':
                assert response.is_json, f"Endpoint {endpoint} did not return JSON"
    
    def test_response_format_consistency(self, client: FlaskClient) -> None:
        """
        Test response format consistency across endpoints.
        
        Validates all JSON endpoints follow consistent response
        format for client application compatibility.
        """
        json_endpoints = ['/', '/health', '/health/readiness', '/health/detailed', '/status', '/version']
        
        for endpoint in json_endpoints:
            response = client.get(endpoint)
            
            if response.status_code != 200:
                continue  # Skip if endpoint is not healthy
            
            data = response.get_json()
            
            # Standard response format validation
            assert 'success' in data, f"Endpoint {endpoint} missing 'success' field"
            assert 'correlation_id' in data, f"Endpoint {endpoint} missing 'correlation_id' field"
            
            if data['success']:
                assert 'data' in data, f"Successful endpoint {endpoint} missing 'data' field"
                assert 'message' in data, f"Successful endpoint {endpoint} missing 'message' field"
            else:
                assert 'error' in data, f"Failed endpoint {endpoint} missing 'error' field"
    
    def test_error_response_consistency(self, client: FlaskClient) -> None:
        """
        Test error response format consistency.
        
        Validates error responses follow consistent format
        across all error scenarios for client reliability.
        """
        # Test 404 error
        response = client.get('/nonexistent')
        assert response.status_code == 404
        
        data = response.get_json()
        assert data['success'] is False
        assert 'error' in data
        assert 'error_code' in data
        assert 'correlation_id' in data
        
        error_info = data['error']
        assert 'message' in error_info
        assert 'status_code' in error_info
        assert 'details' in error_info
    
    def test_security_headers_completeness(self, client: FlaskClient) -> None:
        """
        Test security headers completeness for production.
        
        Validates all security headers are properly set
        per Section 6.4.3.4 security requirements.
        """
        response = client.get('/')
        
        required_security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for header, expected_value in required_security_headers.items():
            assert header in response.headers, f"Missing security header: {header}"
            assert response.headers[header] == expected_value, f"Incorrect value for {header}"
    
    def test_monitoring_integration_readiness(self, client: FlaskClient) -> None:
        """
        Test monitoring integration readiness for production.
        
        Validates monitoring endpoints provide necessary information
        for production observability per Section 6.5 requirements.
        """
        # Test health check endpoints
        health_response = client.get('/health')
        assert health_response.status_code == 200
        
        # Test metrics endpoint
        metrics_response = client.get('/metrics')
        assert metrics_response.status_code == 200
        assert 'text/plain' in metrics_response.headers['Content-Type']
        
        # Test status endpoint
        status_response = client.get('/status')
        assert status_response.status_code == 200
        
        status_data = status_response.get_json()['data']
        config = status_data['configuration']
        
        # Validate monitoring capabilities are enabled
        assert config['monitoring_enabled'] is True
        assert config['health_checks_enabled'] is True
        assert config['metrics_enabled'] is True
    
    @pytest.mark.comparative
    def test_feature_parity_validation(self, client: FlaskClient) -> None:
        """
        Test feature parity with Node.js implementation.
        
        Validates Flask implementation maintains feature parity
        with original Node.js system per Feature F-001 requirements.
        """
        # Test index route provides equivalent information
        response = client.get('/')
        assert response.status_code == 200
        
        data = response.get_json()['data']
        
        # Validate migration status information
        assert data['migration_status'] == 'active'
        assert 'Python 3.13.3/Flask 3.1.1 migration' in data['description']
        
        # Test health endpoints provide equivalent functionality
        health_response = client.get('/health')
        assert health_response.status_code == 200
        
        health_data = health_response.get_json()['data']
        assert health_data['status'] == 'healthy'
        assert 'response_time_seconds' in health_data
        
        # Test version information provides migration details
        version_response = client.get('/version')
        assert version_response.status_code == 200
        
        version_data = version_response.get_json()['data']
        migration_info = version_data['migration_info']
        assert migration_info['source_technology'] == 'Node.js/Express.js'
        assert migration_info['target_technology'] == 'Python 3.13.3/Flask 3.1.1'
        assert migration_info['migration_status'] == 'completed'


class TestBlueprintIntegration:
    """
    Test class for Flask blueprint integration functionality.
    
    Validates main blueprint integration with Flask application
    factory pattern per Section 5.1.1 requirements.
    """
    
    def test_blueprint_registration(self, app: Flask) -> None:
        """
        Test main blueprint is properly registered.
        
        Validates blueprint registration in Flask application
        factory pattern per Section 5.1.1.
        """
        # Assert blueprint is registered
        assert 'main' in app.blueprints
        
        main_blueprint = app.blueprints['main']
        assert main_blueprint.name == 'main'
        assert main_blueprint.url_prefix == '/'
    
    def test_blueprint_route_registration(self, app: Flask) -> None:
        """
        Test main blueprint routes are properly registered.
        
        Validates all main blueprint routes are accessible
        through Flask application routing system.
        """
        with app.app_context():
            # Get all registered routes
            routes = []
            for rule in app.url_map.iter_rules():
                if rule.endpoint.startswith('main.'):
                    routes.append(rule.endpoint)
            
            # Validate expected routes are registered
            expected_routes = [
                'main.index',
                'main.health_liveness',
                'main.health_readiness',
                'main.health_detailed',
                'main.prometheus_metrics',
                'main.system_status',
                'main.application_version'
            ]
            
            for expected_route in expected_routes:
                assert expected_route in routes, f"Route {expected_route} not registered"
    
    def test_blueprint_configuration(self, app: Flask) -> None:
        """
        Test main blueprint configuration is properly set.
        
        Validates blueprint-specific configuration settings
        are applied during application initialization.
        """
        # Test blueprint-specific configuration
        assert app.config.get('MAIN_BLUEPRINT_ENABLED', False) is True
        assert app.config.get('HEALTH_CHECK_TIMEOUT') is not None
        assert app.config.get('METRICS_CACHE_TTL') is not None
        
        # Test application has blueprint metrics counters
        assert hasattr(app, '_main_bp_request_count')
        assert hasattr(app, '_liveness_check_count')
        assert hasattr(app, '_readiness_check_count')
        assert hasattr(app, '_detailed_check_count')
    
    def test_blueprint_error_handlers(self, client: FlaskClient) -> None:
        """
        Test main blueprint error handlers are properly configured.
        
        Validates blueprint-specific error handlers provide
        proper error responses per Section 4.3.2.
        """
        # Test 404 error handler
        response = client.get('/nonexistent-main-route')
        assert response.status_code == 404
        
        data = response.get_json()
        assert 'blueprint' in data['error']['details']
        assert data['error']['details']['blueprint'] == 'main'
        
        # Test error response includes blueprint context
        assert data['error_code'] == 'RESOURCE_NOT_FOUND'
        assert 'correlation_id' in data


# ================================================================================================
# INTEGRATION TEST UTILITIES AND HELPERS
# ================================================================================================

class TestUtilities:
    """
    Utility methods for integration testing support.
    """
    
    @staticmethod
    def validate_response_structure(response_data: Dict[str, Any], success: bool = True) -> None:
        """
        Validate standard response structure for consistency testing.
        
        Args:
            response_data: Response data to validate
            success: Expected success status
        """
        assert 'success' in response_data
        assert response_data['success'] == success
        assert 'correlation_id' in response_data
        
        if success:
            assert 'data' in response_data
            assert 'message' in response_data
        else:
            assert 'error' in response_data
            assert 'error_code' in response_data
    
    @staticmethod
    def validate_health_response(health_data: Dict[str, Any], expected_status: str = 'healthy') -> None:
        """
        Validate health check response structure.
        
        Args:
            health_data: Health response data to validate
            expected_status: Expected health status
        """
        assert 'status' in health_data
        assert health_data['status'] == expected_status
        assert 'timestamp' in health_data
        assert 'response_time_seconds' in health_data
        assert 'check_type' in health_data
    
    @staticmethod
    def validate_security_headers(headers: Dict[str, str]) -> None:
        """
        Validate security headers are properly set.
        
        Args:
            headers: Response headers to validate
        """
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
        
        for header, expected_value in required_headers.items():
            assert header in headers
            assert headers[header] == expected_value
    
    @staticmethod
    def measure_response_time(client: FlaskClient, endpoint: str, method: str = 'GET') -> float:
        """
        Measure endpoint response time for performance testing.
        
        Args:
            client: Flask test client
            endpoint: Endpoint to test
            method: HTTP method to use
            
        Returns:
            Response time in seconds
        """
        start_time = time.time()
        
        if method == 'GET':
            response = client.get(endpoint)
        elif method == 'POST':
            response = client.post(endpoint)
        elif method == 'PUT':
            response = client.put(endpoint)
        elif method == 'DELETE':
            response = client.delete(endpoint)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        end_time = time.time()
        
        assert response.status_code in [200, 201, 204, 404, 405, 503]
        return end_time - start_time


# ================================================================================================
# PYTEST MARKERS AND CONFIGURATION
# ================================================================================================

# Apply integration test markers
pytestmark.extend([
    pytest.mark.main_blueprint,
    pytest.mark.health_checks,
    pytest.mark.monitoring,
    pytest.mark.production_ready
])