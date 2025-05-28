"""
Main Application Blueprint

This module implements the main application blueprint handling primary application routes,
health checks, and core system endpoints that don't fall under API or authentication categories.
This blueprint provides essential system monitoring endpoints and general application functionality
converted from Express.js route handlers per the Flask migration requirements.

The blueprint integrates with Flask's application factory pattern and provides comprehensive
health monitoring, system status endpoints, and core application routing functionality for
production deployment per Section 8.5 monitoring requirements.

Features:
- Main application route conversion maintaining system functionality per Feature F-001
- Health check and monitoring endpoint implementation per Section 8.5
- Flask error handling with standardized error responses per Section 4.3.2
- System status and monitoring integration per Section 5.1.4
- Production-ready endpoint implementation per Section 8.1

Technical Requirements:
- Flask 3.1.1 blueprint with @blueprint.route decorators
- Integration with prometheus_flask_exporter for metrics collection
- Health check endpoints for container orchestration
- Standardized JSON response formatting
- Comprehensive error handling and logging

Author: Flask Migration Team
Version: 1.0.0
Python: 3.13.3
Flask: 3.1.1
"""

from flask import Blueprint, request, current_app, jsonify
from datetime import datetime, timezone
import sys
import os
import psutil
import platform
from typing import Dict, Any, Optional, Tuple

# Import application utilities
from src.utils.monitoring import (
    get_application_health,
    get_database_health,
    get_system_metrics,
    check_external_dependencies,
    get_prometheus_metrics
)
from src.utils.response import (
    success_response,
    error_response,
    health_response,
    metrics_response
)
from src.utils.error_handling import (
    handle_application_error,
    log_system_error,
    create_error_context
)
from src.utils.logging import get_logger, create_correlation_id
from src.utils.datetime import utc_now, format_datetime
from src.utils.validation import validate_request_params

# Initialize structured logger for this module
logger = get_logger(__name__)

# Create main blueprint with URL prefix for organized routing
main_bp = Blueprint(
    'main',
    __name__,
    url_prefix='/',
    static_folder=None,
    template_folder=None
)

# Blueprint configuration for monitoring and observability
BLUEPRINT_NAME = 'main'
BLUEPRINT_VERSION = '1.0.0'
HEALTH_CHECK_TIMEOUT = 30  # seconds
METRICS_CACHE_TTL = 60     # seconds


@main_bp.before_request
def before_main_request() -> Optional[Any]:
    """
    Pre-request processing for main blueprint requests.
    
    Implements Flask before_request handler replacing Express.js middleware patterns
    per Section 4.3.2. Provides request correlation ID generation, basic request
    validation, and request timing for monitoring and observability.
    
    Returns:
        None or Response object if request should be terminated
    """
    try:
        # Generate correlation ID for request tracking
        correlation_id = create_correlation_id()
        request.correlation_id = correlation_id
        request.start_time = datetime.now(timezone.utc)
        
        # Log incoming request for audit and monitoring
        logger.info(
            "Main blueprint request initiated",
            extra={
                'correlation_id': correlation_id,
                'endpoint': request.endpoint,
                'method': request.method,
                'path': request.path,
                'remote_addr': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'blueprint': BLUEPRINT_NAME
            }
        )
        
        # Basic request validation for security
        if request.content_length and request.content_length > 1024 * 1024:  # 1MB limit
            logger.warning(
                "Request size exceeds limit",
                extra={
                    'correlation_id': correlation_id,
                    'content_length': request.content_length,
                    'max_allowed': 1024 * 1024
                }
            )
            return error_response(
                message="Request size too large",
                status_code=413,
                correlation_id=correlation_id
            )
            
    except Exception as e:
        # Handle pre-request errors gracefully
        logger.error(
            "Error in main blueprint before_request handler",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'endpoint': getattr(request, 'endpoint', 'unknown'),
                'method': getattr(request, 'method', 'unknown')
            }
        )
        return error_response(
            message="Internal server error during request processing",
            status_code=500
        )


@main_bp.after_request
def after_main_request(response) -> Any:
    """
    Post-request processing for main blueprint responses.
    
    Implements Flask after_request handler for response modification, cleanup
    operations, and audit logging per Section 4.3.2. Adds security headers,
    calculates request duration, and logs response details for monitoring.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified Flask response object
    """
    try:
        # Calculate request duration for performance monitoring
        if hasattr(request, 'start_time'):
            duration = (datetime.now(timezone.utc) - request.start_time).total_seconds()
            response.headers['X-Response-Time'] = f"{duration:.3f}s"
        
        # Add security headers per Section 6.4.3.4
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add correlation ID to response headers for debugging
        if hasattr(request, 'correlation_id'):
            response.headers['X-Correlation-ID'] = request.correlation_id
        
        # Log response for audit and monitoring
        logger.info(
            "Main blueprint request completed",
            extra={
                'correlation_id': getattr(request, 'correlation_id', 'unknown'),
                'status_code': response.status_code,
                'content_length': response.content_length,
                'duration_seconds': duration if hasattr(request, 'start_time') else None,
                'blueprint': BLUEPRINT_NAME
            }
        )
        
    except Exception as e:
        # Log errors but don't fail the response
        logger.error(
            "Error in main blueprint after_request handler",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'status_code': response.status_code
            }
        )
    
    return response


@main_bp.route('/', methods=['GET'])
def index() -> Tuple[Dict[str, Any], int]:
    """
    Main application index route.
    
    Provides basic application information and status for the root endpoint.
    Converts Express.js main route handlers to Flask blueprint per Feature F-001
    while maintaining system functionality and providing essential application metadata.
    
    Returns:
        Tuple[Dict[str, Any], int]: JSON response with application info and HTTP status
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        
        logger.info(
            "Index route accessed",
            extra={
                'correlation_id': correlation_id,
                'endpoint': 'index'
            }
        )
        
        # Application information
        app_info = {
            'application': 'Flask Application',
            'description': 'Python 3.13.3/Flask 3.1.1 migration from Node.js/Express.js',
            'version': current_app.config.get('APPLICATION_VERSION', '1.0.0'),
            'environment': current_app.config.get('ENVIRONMENT', 'production'),
            'python_version': platform.python_version(),
            'platform': platform.platform(),
            'timestamp': format_datetime(utc_now()),
            'blueprint': BLUEPRINT_NAME,
            'migration_status': 'active'
        }
        
        return success_response(
            data=app_info,
            message="Application is running successfully",
            correlation_id=correlation_id
        ), 200
        
    except Exception as e:
        logger.error(
            "Error in index route",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return handle_application_error(e, 'index_route_error')


@main_bp.route('/health', methods=['GET'])
@main_bp.route('/health/liveness', methods=['GET'])
def health_liveness() -> Tuple[Dict[str, Any], int]:
    """
    Liveness probe endpoint for container orchestration.
    
    Implements basic application responsiveness check for Kubernetes/ECS liveness probe
    per Section 6.5.2.1. Provides fast response (<50ms requirement) indicating the
    application is alive and accepting requests.
    
    Returns:
        Tuple[Dict[str, Any], int]: Health status response and HTTP status code
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        start_time = datetime.now(timezone.utc)
        
        # Basic liveness check - just confirm application is responsive
        status = 'healthy'
        message = 'Application is alive and responding'
        
        # Calculate response time for monitoring
        response_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        health_data = {
            'status': status,
            'timestamp': format_datetime(utc_now()),
            'response_time_seconds': response_time,
            'check_type': 'liveness',
            'application_version': current_app.config.get('APPLICATION_VERSION', '1.0.0'),
            'python_version': platform.python_version()
        }
        
        logger.info(
            "Liveness check completed",
            extra={
                'correlation_id': correlation_id,
                'status': status,
                'response_time': response_time,
                'check_type': 'liveness'
            }
        )
        
        return health_response(
            status=status,
            data=health_data,
            message=message,
            correlation_id=correlation_id
        ), 200
        
    except Exception as e:
        logger.error(
            "Error in liveness probe",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return health_response(
            status='unhealthy',
            data={'error': str(e)},
            message='Liveness check failed',
            correlation_id=getattr(request, 'correlation_id', 'unknown')
        ), 503


@main_bp.route('/health/readiness', methods=['GET'])
def health_readiness() -> Tuple[Dict[str, Any], int]:
    """
    Readiness probe endpoint for container orchestration.
    
    Implements comprehensive system readiness check for Kubernetes/ECS readiness probe
    per Section 6.5.2.1. Validates database connectivity, external dependencies,
    and application configuration within 100ms requirement.
    
    Returns:
        Tuple[Dict[str, Any], int]: Readiness status response and HTTP status code
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        start_time = datetime.now(timezone.utc)
        
        logger.info(
            "Readiness check initiated",
            extra={
                'correlation_id': correlation_id,
                'check_type': 'readiness'
            }
        )
        
        # Comprehensive readiness checks
        checks = {}
        overall_status = 'healthy'
        
        # 1. Application health check
        try:
            app_health = get_application_health()
            checks['application'] = {
                'status': 'healthy' if app_health['healthy'] else 'unhealthy',
                'details': app_health
            }
            if not app_health['healthy']:
                overall_status = 'degraded'
        except Exception as e:
            checks['application'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_status = 'unhealthy'
        
        # 2. Database connectivity check
        try:
            db_health = get_database_health()
            checks['database'] = {
                'status': 'healthy' if db_health['connected'] else 'unhealthy',
                'details': db_health
            }
            if not db_health['connected']:
                overall_status = 'unhealthy'
        except Exception as e:
            checks['database'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            overall_status = 'unhealthy'
        
        # 3. External dependencies check
        try:
            deps_health = check_external_dependencies()
            checks['external_dependencies'] = {
                'status': 'healthy' if deps_health['all_healthy'] else 'degraded',
                'details': deps_health
            }
            if not deps_health['all_healthy']:
                overall_status = 'degraded'
        except Exception as e:
            checks['external_dependencies'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            if overall_status == 'healthy':
                overall_status = 'degraded'
        
        # Calculate total response time
        response_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Prepare response data
        health_data = {
            'status': overall_status,
            'timestamp': format_datetime(utc_now()),
            'response_time_seconds': response_time,
            'check_type': 'readiness',
            'checks': checks,
            'application_version': current_app.config.get('APPLICATION_VERSION', '1.0.0')
        }
        
        # Determine HTTP status code based on health
        status_code = 200 if overall_status in ['healthy', 'degraded'] else 503
        
        logger.info(
            "Readiness check completed",
            extra={
                'correlation_id': correlation_id,
                'overall_status': overall_status,
                'response_time': response_time,
                'checks_passed': sum(1 for check in checks.values() if check['status'] == 'healthy'),
                'total_checks': len(checks)
            }
        )
        
        return health_response(
            status=overall_status,
            data=health_data,
            message=f"System readiness check completed - {overall_status}",
            correlation_id=correlation_id
        ), status_code
        
    except Exception as e:
        logger.error(
            "Error in readiness probe",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return health_response(
            status='unhealthy',
            data={'error': str(e)},
            message='Readiness check failed',
            correlation_id=getattr(request, 'correlation_id', 'unknown')
        ), 503


@main_bp.route('/health/detailed', methods=['GET'])
def health_detailed() -> Tuple[Dict[str, Any], int]:
    """
    Comprehensive system health endpoint for administrative monitoring.
    
    Provides detailed system status including resource utilization, performance metrics,
    database statistics, and external service health per Section 6.5.2.1. Used for
    administrative monitoring with detailed Flask application state within 200ms requirement.
    
    Returns:
        Tuple[Dict[str, Any], int]: Detailed health information and HTTP status code
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        start_time = datetime.now(timezone.utc)
        
        logger.info(
            "Detailed health check initiated",
            extra={
                'correlation_id': correlation_id,
                'check_type': 'detailed'
            }
        )
        
        # Gather comprehensive system information
        health_details = {}
        
        # 1. Application health and configuration
        try:
            app_health = get_application_health()
            health_details['application'] = {
                'status': 'healthy' if app_health['healthy'] else 'unhealthy',
                'version': current_app.config.get('APPLICATION_VERSION', '1.0.0'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'debug_mode': current_app.debug,
                'testing_mode': current_app.testing,
                'blueprint_count': len(current_app.blueprints),
                'registered_blueprints': list(current_app.blueprints.keys()),
                'details': app_health
            }
        except Exception as e:
            health_details['application'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # 2. System metrics and resource utilization
        try:
            system_metrics = get_system_metrics()
            health_details['system'] = {
                'status': 'healthy',
                'python_version': platform.python_version(),
                'platform': platform.platform(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'memory_usage': {
                    'total_mb': round(psutil.virtual_memory().total / 1024 / 1024, 2),
                    'available_mb': round(psutil.virtual_memory().available / 1024 / 1024, 2),
                    'percent_used': psutil.virtual_memory().percent,
                    'process_memory_mb': round(psutil.Process().memory_info().rss / 1024 / 1024, 2)
                },
                'cpu_usage': {
                    'percent': psutil.cpu_percent(interval=None),
                    'count': psutil.cpu_count(),
                    'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else None
                },
                'disk_usage': {
                    'total_gb': round(psutil.disk_usage('/').total / 1024 / 1024 / 1024, 2),
                    'free_gb': round(psutil.disk_usage('/').free / 1024 / 1024 / 1024, 2),
                    'percent_used': psutil.disk_usage('/').percent
                },
                'details': system_metrics
            }
        except Exception as e:
            health_details['system'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # 3. Database health and statistics
        try:
            db_health = get_database_health()
            health_details['database'] = {
                'status': 'healthy' if db_health['connected'] else 'unhealthy',
                'details': db_health
            }
        except Exception as e:
            health_details['database'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # 4. External dependencies status
        try:
            deps_health = check_external_dependencies()
            health_details['external_dependencies'] = {
                'status': 'healthy' if deps_health['all_healthy'] else 'degraded',
                'details': deps_health
            }
        except Exception as e:
            health_details['external_dependencies'] = {
                'status': 'error',
                'error': str(e)
            }
        
        # Calculate response time
        response_time = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        # Determine overall system status
        component_statuses = [details.get('status', 'unknown') for details in health_details.values()]
        if any(status == 'unhealthy' for status in component_statuses):
            overall_status = 'unhealthy'
        elif any(status in ['degraded', 'error'] for status in component_statuses):
            overall_status = 'degraded'
        else:
            overall_status = 'healthy'
        
        # Prepare comprehensive response
        detailed_health = {
            'overall_status': overall_status,
            'timestamp': format_datetime(utc_now()),
            'response_time_seconds': response_time,
            'check_type': 'detailed',
            'uptime_seconds': (datetime.now(timezone.utc) - datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)).total_seconds(),
            'components': health_details,
            'summary': {
                'total_components': len(health_details),
                'healthy_components': sum(1 for details in health_details.values() if details.get('status') == 'healthy'),
                'degraded_components': sum(1 for details in health_details.values() if details.get('status') == 'degraded'),
                'unhealthy_components': sum(1 for details in health_details.values() if details.get('status') == 'unhealthy'),
                'error_components': sum(1 for details in health_details.values() if details.get('status') == 'error')
            }
        }
        
        logger.info(
            "Detailed health check completed",
            extra={
                'correlation_id': correlation_id,
                'overall_status': overall_status,
                'response_time': response_time,
                'component_count': len(health_details),
                'healthy_count': detailed_health['summary']['healthy_components']
            }
        )
        
        return health_response(
            status=overall_status,
            data=detailed_health,
            message=f"Detailed system health check completed - {overall_status}",
            correlation_id=correlation_id
        ), 200
        
    except Exception as e:
        logger.error(
            "Error in detailed health check",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return health_response(
            status='unhealthy',
            data={'error': str(e)},
            message='Detailed health check failed',
            correlation_id=getattr(request, 'correlation_id', 'unknown')
        ), 500


@main_bp.route('/metrics', methods=['GET'])
def prometheus_metrics() -> Tuple[str, int, Dict[str, str]]:
    """
    Prometheus metrics endpoint for monitoring and observability.
    
    Exposes application metrics in Prometheus format for collection by monitoring
    infrastructure per Section 6.5.1.1. Integrates with prometheus_flask_exporter
    for comprehensive Flask application monitoring including response times,
    throughput, and custom business metrics.
    
    Returns:
        Tuple[str, int, Dict[str, str]]: Prometheus metrics text, HTTP status, headers
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        
        logger.info(
            "Prometheus metrics requested",
            extra={
                'correlation_id': correlation_id,
                'endpoint': 'metrics'
            }
        )
        
        # Get Prometheus metrics from monitoring utilities
        metrics_data = get_prometheus_metrics()
        
        # Additional custom metrics for main blueprint
        custom_metrics = f"""
# HELP flask_main_blueprint_requests_total Total requests to main blueprint
# TYPE flask_main_blueprint_requests_total counter
flask_main_blueprint_requests_total{{blueprint="{BLUEPRINT_NAME}",version="{BLUEPRINT_VERSION}"}} {getattr(current_app, '_main_bp_request_count', 0)}

# HELP flask_main_blueprint_health_checks_total Total health check requests
# TYPE flask_main_blueprint_health_checks_total counter
flask_main_blueprint_health_checks_total{{check_type="liveness"}} {getattr(current_app, '_liveness_check_count', 0)}
flask_main_blueprint_health_checks_total{{check_type="readiness"}} {getattr(current_app, '_readiness_check_count', 0)}
flask_main_blueprint_health_checks_total{{check_type="detailed"}} {getattr(current_app, '_detailed_check_count', 0)}

# HELP flask_application_info Application information
# TYPE flask_application_info gauge
flask_application_info{{version="{current_app.config.get('APPLICATION_VERSION', '1.0.0')}",environment="{current_app.config.get('ENVIRONMENT', 'production')}",python_version="{platform.python_version()}"}} 1
"""
        
        # Combine metrics
        full_metrics = metrics_data + custom_metrics
        
        # Set response headers for Prometheus
        headers = {
            'Content-Type': 'text/plain; version=0.0.4; charset=utf-8',
            'X-Correlation-ID': correlation_id
        }
        
        return full_metrics, 200, headers
        
    except Exception as e:
        logger.error(
            "Error generating Prometheus metrics",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return "# Error generating metrics\n", 500, {'Content-Type': 'text/plain'}


@main_bp.route('/status', methods=['GET'])
def system_status() -> Tuple[Dict[str, Any], int]:
    """
    System status endpoint for monitoring and observability.
    
    Provides system status information for production monitoring per Section 5.1.4.
    Returns comprehensive system state including application version, environment,
    configuration status, and key system indicators.
    
    Returns:
        Tuple[Dict[str, Any], int]: System status response and HTTP status code
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        
        logger.info(
            "System status requested",
            extra={
                'correlation_id': correlation_id,
                'endpoint': 'status'
            }
        )
        
        # Gather system status information
        status_data = {
            'application': {
                'name': 'Flask Application',
                'version': current_app.config.get('APPLICATION_VERSION', '1.0.0'),
                'environment': current_app.config.get('ENVIRONMENT', 'production'),
                'debug_mode': current_app.debug,
                'testing_mode': current_app.testing,
                'migration_status': 'active',
                'framework': f"Flask {current_app.config.get('FLASK_VERSION', '3.1.1')}",
                'python_version': platform.python_version()
            },
            'system': {
                'platform': platform.platform(),
                'architecture': platform.architecture()[0],
                'hostname': platform.node(),
                'pid': os.getpid(),
                'uptime_seconds': (datetime.now(timezone.utc) - datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)).total_seconds()
            },
            'configuration': {
                'database_configured': bool(current_app.config.get('SQLALCHEMY_DATABASE_URI')),
                'monitoring_enabled': True,
                'health_checks_enabled': True,
                'metrics_enabled': True,
                'logging_configured': bool(current_app.config.get('LOGGING_CONFIG'))
            },
            'blueprints': {
                'registered_count': len(current_app.blueprints),
                'blueprints': list(current_app.blueprints.keys())
            },
            'timestamp': format_datetime(utc_now()),
            'request_id': correlation_id
        }
        
        return success_response(
            data=status_data,
            message="System status retrieved successfully",
            correlation_id=correlation_id
        ), 200
        
    except Exception as e:
        logger.error(
            "Error retrieving system status",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return handle_application_error(e, 'system_status_error')


@main_bp.route('/version', methods=['GET'])
def application_version() -> Tuple[Dict[str, Any], int]:
    """
    Application version endpoint.
    
    Returns application version information including Flask version, Python version,
    build information, and migration status. Useful for deployment verification
    and version tracking in production environments.
    
    Returns:
        Tuple[Dict[str, Any], int]: Version information response and HTTP status code
    """
    try:
        correlation_id = getattr(request, 'correlation_id', create_correlation_id())
        
        version_info = {
            'application_version': current_app.config.get('APPLICATION_VERSION', '1.0.0'),
            'framework_versions': {
                'flask': current_app.config.get('FLASK_VERSION', '3.1.1'),
                'python': platform.python_version(),
                'werkzeug': current_app.config.get('WERKZEUG_VERSION', '3.1+'),
                'sqlalchemy': current_app.config.get('SQLALCHEMY_VERSION', '3.1.1')
            },
            'build_info': {
                'build_date': current_app.config.get('BUILD_DATE', format_datetime(utc_now())),
                'build_number': current_app.config.get('BUILD_NUMBER', 'unknown'),
                'git_commit': current_app.config.get('GIT_COMMIT', 'unknown'),
                'environment': current_app.config.get('ENVIRONMENT', 'production')
            },
            'migration_info': {
                'migration_status': 'completed',
                'source_technology': 'Node.js/Express.js',
                'target_technology': 'Python 3.13.3/Flask 3.1.1',
                'migration_date': current_app.config.get('MIGRATION_DATE', '2024-01-01')
            },
            'timestamp': format_datetime(utc_now()),
            'request_id': correlation_id
        }
        
        logger.info(
            "Version information requested",
            extra={
                'correlation_id': correlation_id,
                'application_version': version_info['application_version'],
                'environment': version_info['build_info']['environment']
            }
        )
        
        return success_response(
            data=version_info,
            message="Version information retrieved successfully",
            correlation_id=correlation_id
        ), 200
        
    except Exception as e:
        logger.error(
            "Error retrieving version information",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'correlation_id': getattr(request, 'correlation_id', 'unknown')
            }
        )
        return handle_application_error(e, 'version_info_error')


# Error handlers for main blueprint
@main_bp.errorhandler(404)
def handle_not_found(error) -> Tuple[Dict[str, Any], int]:
    """
    Handle 404 Not Found errors for main blueprint.
    
    Implements Flask @app.errorhandler decorator for standardized error responses
    per Section 4.3.2. Provides consistent error formatting and logging for
    not found errors within the main blueprint scope.
    
    Args:
        error: Flask error object
        
    Returns:
        Tuple[Dict[str, Any], int]: Error response and HTTP status code
    """
    correlation_id = getattr(request, 'correlation_id', create_correlation_id())
    
    logger.warning(
        "Main blueprint 404 error",
        extra={
            'correlation_id': correlation_id,
            'path': request.path,
            'method': request.method,
            'endpoint': request.endpoint,
            'blueprint': BLUEPRINT_NAME
        }
    )
    
    return error_response(
        message="The requested resource was not found",
        status_code=404,
        error_code="RESOURCE_NOT_FOUND",
        correlation_id=correlation_id,
        details={
            'path': request.path,
            'method': request.method,
            'blueprint': BLUEPRINT_NAME
        }
    ), 404


@main_bp.errorhandler(500)
def handle_internal_error(error) -> Tuple[Dict[str, Any], int]:
    """
    Handle 500 Internal Server Error for main blueprint.
    
    Implements Flask @app.errorhandler decorator for standardized error responses
    per Section 4.3.2. Provides comprehensive error logging and secure error
    responses for internal server errors within the main blueprint.
    
    Args:
        error: Flask error object
        
    Returns:
        Tuple[Dict[str, Any], int]: Error response and HTTP status code
    """
    correlation_id = getattr(request, 'correlation_id', create_correlation_id())
    
    # Log detailed error information for debugging
    error_context = create_error_context(error, request)
    log_system_error(error, error_context, correlation_id)
    
    logger.error(
        "Main blueprint 500 error",
        extra={
            'correlation_id': correlation_id,
            'error': str(error),
            'error_type': type(error).__name__,
            'path': request.path,
            'method': request.method,
            'blueprint': BLUEPRINT_NAME,
            'error_context': error_context
        }
    )
    
    return error_response(
        message="An internal server error occurred",
        status_code=500,
        error_code="INTERNAL_SERVER_ERROR",
        correlation_id=correlation_id,
        details={
            'blueprint': BLUEPRINT_NAME,
            'timestamp': format_datetime(utc_now())
        }
    ), 500


@main_bp.errorhandler(Exception)
def handle_general_exception(error) -> Tuple[Dict[str, Any], int]:
    """
    Handle general exceptions for main blueprint.
    
    Catch-all error handler for unhandled exceptions in the main blueprint.
    Provides consistent error logging and response formatting while ensuring
    no sensitive information is exposed in error responses.
    
    Args:
        error: Exception object
        
    Returns:
        Tuple[Dict[str, Any], int]: Error response and HTTP status code
    """
    correlation_id = getattr(request, 'correlation_id', create_correlation_id())
    
    # Create comprehensive error context for debugging
    error_context = create_error_context(error, request)
    log_system_error(error, error_context, correlation_id)
    
    logger.error(
        "Unhandled exception in main blueprint",
        extra={
            'correlation_id': correlation_id,
            'error': str(error),
            'error_type': type(error).__name__,
            'path': request.path,
            'method': request.method,
            'blueprint': BLUEPRINT_NAME,
            'error_context': error_context
        }
    )
    
    return error_response(
        message="An unexpected error occurred",
        status_code=500,
        error_code="UNEXPECTED_ERROR",
        correlation_id=correlation_id,
        details={
            'blueprint': BLUEPRINT_NAME,
            'error_type': type(error).__name__,
            'timestamp': format_datetime(utc_now())
        }
    ), 500


# Blueprint registration and initialization
def init_main_blueprint(app) -> None:
    """
    Initialize main blueprint with application-specific configuration.
    
    Performs blueprint-specific initialization including metrics setup,
    health check configuration, and monitoring integration per Flask
    application factory pattern requirements.
    
    Args:
        app: Flask application instance
    """
    try:
        # Initialize blueprint-specific metrics counters
        app._main_bp_request_count = 0
        app._liveness_check_count = 0
        app._readiness_check_count = 0
        app._detailed_check_count = 0
        
        # Configure blueprint-specific settings
        app.config.setdefault('MAIN_BLUEPRINT_ENABLED', True)
        app.config.setdefault('HEALTH_CHECK_TIMEOUT', HEALTH_CHECK_TIMEOUT)
        app.config.setdefault('METRICS_CACHE_TTL', METRICS_CACHE_TTL)
        
        logger.info(
            "Main blueprint initialized successfully",
            extra={
                'blueprint': BLUEPRINT_NAME,
                'version': BLUEPRINT_VERSION,
                'health_check_timeout': HEALTH_CHECK_TIMEOUT,
                'metrics_cache_ttl': METRICS_CACHE_TTL
            }
        )
        
    except Exception as e:
        logger.error(
            "Error initializing main blueprint",
            extra={
                'error': str(e),
                'error_type': type(e).__name__,
                'blueprint': BLUEPRINT_NAME
            }
        )
        raise


# Export blueprint for application factory registration
__all__ = ['main_bp', 'init_main_blueprint']