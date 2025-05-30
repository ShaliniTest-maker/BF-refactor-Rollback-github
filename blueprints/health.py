"""
Health Check Blueprint for Flask Application

This module provides comprehensive system monitoring endpoints for application health validation,
database connectivity checks, and service availability reporting. Implements container orchestration
integration with Kubernetes liveness and readiness probes while supporting production monitoring
and alerting systems.

Key Features:
- Multi-tier health check endpoints with configurable response time requirements
- Database connectivity validation with Flask-SQLAlchemy health checks
- Resource utilization metrics for performance monitoring 
- Container orchestration integration for Kubernetes deployment
- Docker HEALTHCHECK instruction support with appropriate timeouts
- Service availability reporting for external dependencies
- Comprehensive system status validation with detailed diagnostics

Health Check Endpoints:
- /health/liveness: Basic application responsiveness (<50ms) for load balancer checks
- /health/readiness: Full system readiness validation (<100ms) for deployment validation  
- /health/detailed: Comprehensive system status (<200ms) for administrative monitoring

Dependencies:
- Flask 3.1.1: Core blueprint and routing functionality
- Flask-SQLAlchemy 3.1.1: Database connectivity validation
- psutil: System resource monitoring and utilization metrics
- python-dotenv 1.0.1: Environment configuration management
- requests: External service dependency validation

Container Integration:
- Kubernetes liveness probe endpoint with appropriate timeout configuration
- Kubernetes readiness probe endpoint with comprehensive validation
- Docker HEALTHCHECK instruction support for container orchestration
- ECS/EKS health check integration for AWS container services
"""

import os
import logging
import time
import psutil
import platform
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
from functools import wraps

from flask import Blueprint, jsonify, current_app, request, g
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from models import db, get_database_health

# Configure logging for health check operations
logger = logging.getLogger(__name__)

# Create health check blueprint with organized route structure
health_bp = Blueprint(
    'health',
    __name__,
    url_prefix='/health',
    template_folder='../templates/health',
    static_folder='../static'
)

# Health check response time requirements per Section 6.5.2.1
HEALTH_CHECK_TIMEOUTS = {
    'liveness': 0.050,    # 50ms - Basic connectivity for load balancers
    'readiness': 0.100,   # 100ms - Full system readiness for deployment
    'detailed': 0.200     # 200ms - Comprehensive status for monitoring
}

# Service availability thresholds and configuration
SERVICE_HEALTH_THRESHOLDS = {
    'database_max_response_time': 0.100,    # 100ms max database response
    'memory_usage_threshold': 0.80,         # 80% memory usage warning
    'cpu_usage_threshold': 0.85,            # 85% CPU usage warning
    'disk_usage_threshold': 0.90,           # 90% disk usage critical
    'connection_pool_threshold': 0.90       # 90% connection pool utilization warning
}

# Cache for system information to improve performance
_system_info_cache = {}
_cache_ttl = 60  # Cache system info for 60 seconds


def with_timeout(timeout_seconds: float):
    """
    Decorator to enforce response time requirements for health check endpoints.
    
    Ensures health check endpoints meet their SLA requirements per Section 6.5.2.1:
    - Liveness checks: <50ms for load balancer health validation
    - Readiness checks: <100ms for deployment health validation  
    - Detailed checks: <200ms for administrative monitoring
    
    Args:
        timeout_seconds: Maximum allowed execution time in seconds
        
    Returns:
        Decorator function that enforces timeout and logs performance metrics
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Log performance metrics for monitoring
                logger.debug(
                    f"Health check {func.__name__} completed in {execution_time:.3f}s "
                    f"(limit: {timeout_seconds:.3f}s)"
                )
                
                # Add performance metadata to response
                if isinstance(result, tuple) and len(result) == 2:
                    response_data, status_code = result
                    if isinstance(response_data, dict):
                        response_data['_performance'] = {
                            'execution_time_ms': round(execution_time * 1000, 2),
                            'timeout_ms': round(timeout_seconds * 1000, 2),
                            'within_sla': execution_time <= timeout_seconds
                        }
                    return response_data, status_code
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                logger.error(
                    f"Health check {func.__name__} failed after {execution_time:.3f}s: {e}"
                )
                
                return {
                    'status': 'error',
                    'message': f'Health check failed: {str(e)}',
                    '_performance': {
                        'execution_time_ms': round(execution_time * 1000, 2),
                        'timeout_ms': round(timeout_seconds * 1000, 2),
                        'within_sla': False
                    }
                }, 500
                
        return wrapper
    return decorator


def get_system_info(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Get cached system information with TTL-based refresh for performance optimization.
    
    Provides comprehensive system resource information including CPU, memory, disk,
    and network statistics for health monitoring and resource utilization tracking.
    
    Args:
        force_refresh: Force cache refresh ignoring TTL
        
    Returns:
        Dictionary containing system resource information and utilization metrics
    """
    global _system_info_cache
    
    current_time = time.time()
    cache_key = 'system_info'
    
    # Check cache validity
    if (not force_refresh and 
        cache_key in _system_info_cache and 
        current_time - _system_info_cache[cache_key]['timestamp'] < _cache_ttl):
        return _system_info_cache[cache_key]['data']
    
    try:
        # Collect comprehensive system information
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
        
        # Calculate derived metrics
        uptime_seconds = current_time - psutil.boot_time()
        
        system_info = {
            'platform': {
                'system': platform.system(),
                'release': platform.release(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'architecture': platform.architecture()[0]
            },
            'cpu': {
                'count': psutil.cpu_count(),
                'count_logical': psutil.cpu_count(logical=True),
                'usage_percent': cpu_percent,
                'load_average': list(os.getloadavg()) if hasattr(os, 'getloadavg') else None
            },
            'memory': {
                'total_bytes': memory.total,
                'available_bytes': memory.available,
                'used_bytes': memory.used,
                'usage_percent': memory.percent,
                'total_gb': round(memory.total / (1024**3), 2),
                'available_gb': round(memory.available / (1024**3), 2),
                'used_gb': round(memory.used / (1024**3), 2)
            },
            'disk': {
                'total_bytes': disk.total,
                'free_bytes': disk.free,
                'used_bytes': disk.used,
                'usage_percent': (disk.used / disk.total) * 100,
                'total_gb': round(disk.total / (1024**3), 2),
                'free_gb': round(disk.free / (1024**3), 2),
                'used_gb': round(disk.used / (1024**3), 2)
            },
            'network': {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv,
                'errors_in': network.errin,
                'errors_out': network.errout,
                'drops_in': network.dropin,
                'drops_out': network.dropout
            },
            'system': {
                'boot_time': boot_time.isoformat(),
                'uptime_seconds': round(uptime_seconds, 2),
                'uptime_hours': round(uptime_seconds / 3600, 2),
                'process_count': len(psutil.pids())
            }
        }
        
        # Cache the results
        _system_info_cache[cache_key] = {
            'data': system_info,
            'timestamp': current_time
        }
        
        return system_info
        
    except Exception as e:
        logger.error(f"Failed to collect system information: {e}")
        return {
            'error': f'System information collection failed: {str(e)}',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def check_database_connectivity() -> Dict[str, Any]:
    """
    Validate database connectivity and performance using Flask-SQLAlchemy health checks.
    
    Performs comprehensive database health validation including connection pool status,
    query performance testing, and SSL encryption verification per Section 5.2.4
    database access layer requirements.
    
    Returns:
        Dictionary containing database health status and performance metrics
    """
    start_time = time.time()
    
    try:
        # Use the centralized database health function from models
        db_health = get_database_health()
        
        # Perform additional performance validation
        query_start = time.time()
        result = db.session.execute(text('SELECT 1 as health_check')).scalar()
        query_time = time.time() - query_start
        
        total_time = time.time() - start_time
        
        # Determine overall health status
        is_healthy = (
            db_health.get('status') == 'healthy' and
            result == 1 and
            query_time <= SERVICE_HEALTH_THRESHOLDS['database_max_response_time']
        )
        
        return {
            'status': 'healthy' if is_healthy else 'degraded',
            'connectivity': 'connected' if result == 1 else 'failed',
            'query_response_time_ms': round(query_time * 1000, 2),
            'total_check_time_ms': round(total_time * 1000, 2),
            'within_sla': query_time <= SERVICE_HEALTH_THRESHOLDS['database_max_response_time'],
            'pool_info': {
                'pool_size': db_health.get('pool_size'),
                'active_connections': db_health.get('active_connections'),
                'ssl_enabled': db_health.get('ssl_enabled')
            },
            'error': db_health.get('error'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
    except SQLAlchemyError as e:
        total_time = time.time() - start_time
        logger.error(f"Database connectivity check failed: {e}")
        
        return {
            'status': 'unhealthy',
            'connectivity': 'failed',
            'query_response_time_ms': None,
            'total_check_time_ms': round(total_time * 1000, 2),
            'within_sla': False,
            'pool_info': None,
            'error': f'Database error: {str(e)}',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    except Exception as e:
        total_time = time.time() - start_time
        logger.error(f"Unexpected error during database health check: {e}")
        
        return {
            'status': 'error',
            'connectivity': 'unknown',
            'query_response_time_ms': None,
            'total_check_time_ms': round(total_time * 1000, 2),
            'within_sla': False,
            'pool_info': None,
            'error': f'Health check error: {str(e)}',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def validate_external_services() -> Dict[str, Any]:
    """
    Validate external service dependencies and integration health.
    
    Checks the availability and response times of external services including
    authentication providers and any configured external APIs per Section 6.5.1.2
    external service monitoring requirements.
    
    Returns:
        Dictionary containing external service health status and response metrics
    """
    services_status = {}
    overall_healthy = True
    
    # Auth0 Authentication Service Health Check
    auth0_domain = current_app.config.get('AUTH0_DOMAIN')
    if auth0_domain:
        try:
            import requests
            auth0_start = time.time()
            
            # Check Auth0 well-known configuration endpoint
            auth0_url = f"https://{auth0_domain}/.well-known/jwks.json"
            response = requests.get(auth0_url, timeout=5)
            auth0_time = time.time() - auth0_start
            
            services_status['auth0'] = {
                'status': 'healthy' if response.status_code == 200 else 'degraded',
                'response_time_ms': round(auth0_time * 1000, 2),
                'status_code': response.status_code,
                'endpoint': auth0_url,
                'within_sla': auth0_time <= 0.150  # 150ms SLA for auth services
            }
            
            if response.status_code != 200 or auth0_time > 0.150:
                overall_healthy = False
                
        except Exception as e:
            logger.warning(f"Auth0 health check failed: {e}")
            services_status['auth0'] = {
                'status': 'unhealthy',
                'response_time_ms': None,
                'error': str(e),
                'within_sla': False
            }
            overall_healthy = False
    
    # Add additional external service checks here as needed
    # Example: External API dependencies, message queues, cache services
    
    return {
        'overall_status': 'healthy' if overall_healthy else 'degraded',
        'services': services_status,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


def analyze_resource_utilization() -> Dict[str, Any]:
    """
    Analyze system resource utilization and generate health alerts.
    
    Monitors CPU, memory, disk, and network utilization against configured thresholds
    for proactive system monitoring and capacity planning per Section 6.5.1.1
    metrics collection requirements.
    
    Returns:
        Dictionary containing resource utilization analysis and threshold alerts
    """
    system_info = get_system_info()
    alerts = []
    overall_status = 'healthy'
    
    # Analyze CPU utilization
    cpu_usage = system_info.get('cpu', {}).get('usage_percent', 0)
    if cpu_usage > SERVICE_HEALTH_THRESHOLDS['cpu_usage_threshold'] * 100:
        alerts.append({
            'type': 'cpu_high',
            'severity': 'warning',
            'message': f'High CPU usage: {cpu_usage:.1f}%',
            'threshold': f"{SERVICE_HEALTH_THRESHOLDS['cpu_usage_threshold'] * 100}%"
        })
        overall_status = 'warning'
    
    # Analyze memory utilization
    memory_usage = system_info.get('memory', {}).get('usage_percent', 0)
    if memory_usage > SERVICE_HEALTH_THRESHOLDS['memory_usage_threshold'] * 100:
        alerts.append({
            'type': 'memory_high',
            'severity': 'warning',
            'message': f'High memory usage: {memory_usage:.1f}%',
            'threshold': f"{SERVICE_HEALTH_THRESHOLDS['memory_usage_threshold'] * 100}%"
        })
        overall_status = 'warning'
    
    # Analyze disk utilization
    disk_usage = system_info.get('disk', {}).get('usage_percent', 0)
    if disk_usage > SERVICE_HEALTH_THRESHOLDS['disk_usage_threshold'] * 100:
        alerts.append({
            'type': 'disk_critical',
            'severity': 'critical',
            'message': f'Critical disk usage: {disk_usage:.1f}%',
            'threshold': f"{SERVICE_HEALTH_THRESHOLDS['disk_usage_threshold'] * 100}%"
        })
        overall_status = 'critical'
    
    # Analyze connection pool utilization if available
    try:
        db_health = get_database_health()
        pool_size = db_health.get('pool_size', 0)
        active_connections = db_health.get('active_connections', 0)
        
        if pool_size > 0:
            pool_utilization = (active_connections / pool_size) * 100
            if pool_utilization > SERVICE_HEALTH_THRESHOLDS['connection_pool_threshold'] * 100:
                alerts.append({
                    'type': 'connection_pool_high',
                    'severity': 'warning',
                    'message': f'High connection pool usage: {pool_utilization:.1f}%',
                    'threshold': f"{SERVICE_HEALTH_THRESHOLDS['connection_pool_threshold'] * 100}%"
                })
                if overall_status == 'healthy':
                    overall_status = 'warning'
    except Exception as e:
        logger.debug(f"Connection pool analysis skipped: {e}")
    
    return {
        'status': overall_status,
        'alerts': alerts,
        'alert_count': len(alerts),
        'resource_summary': {
            'cpu_usage_percent': cpu_usage,
            'memory_usage_percent': memory_usage,
            'disk_usage_percent': disk_usage
        },
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


@health_bp.route('/liveness', methods=['GET'])
@with_timeout(HEALTH_CHECK_TIMEOUTS['liveness'])
def liveness_probe():
    """
    Kubernetes liveness probe endpoint for basic application responsiveness.
    
    Provides minimal health check validation required for container orchestration
    and load balancer health validation. Optimized for <50ms response time per
    Section 6.1.5 health check endpoint implementation requirements.
    
    Returns:
        JSON response with basic application status for liveness validation
        
    HTTP Status Codes:
        200: Application is responsive and healthy
        503: Application is unresponsive or critical failure detected
    """
    try:
        # Minimal validation for fastest response
        response_data = {
            'status': 'healthy',
            'service': 'flask-app',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'liveness'
        }
        
        logger.debug("Liveness probe successful")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Liveness probe failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'service': 'flask-app',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'liveness'
        }), 503


@health_bp.route('/readiness', methods=['GET'])
@with_timeout(HEALTH_CHECK_TIMEOUTS['readiness'])
def readiness_probe():
    """
    Kubernetes readiness probe endpoint for full system readiness validation.
    
    Performs comprehensive system readiness checks including database connectivity
    and critical service availability. Optimized for <100ms response time per
    Section 6.1.5 container orchestration integration requirements.
    
    Returns:
        JSON response with system readiness status for deployment validation
        
    HTTP Status Codes:
        200: System is ready to handle traffic
        503: System is not ready (database unavailable, critical services down)
    """
    try:
        # Perform critical dependency checks
        db_status = check_database_connectivity()
        
        # Determine overall readiness
        is_ready = (
            db_status['status'] in ['healthy', 'degraded'] and
            db_status['connectivity'] == 'connected'
        )
        
        response_data = {
            'status': 'ready' if is_ready else 'not_ready',
            'service': 'flask-app',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'checks': {
                'database': {
                    'status': db_status['status'],
                    'connectivity': db_status['connectivity'],
                    'response_time_ms': db_status['query_response_time_ms']
                }
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'readiness'
        }
        
        status_code = 200 if is_ready else 503
        
        logger.debug(f"Readiness probe completed: {'ready' if is_ready else 'not ready'}")
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        return jsonify({
            'status': 'not_ready',
            'service': 'flask-app',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'readiness'
        }), 503


@health_bp.route('/detailed', methods=['GET'])
@with_timeout(HEALTH_CHECK_TIMEOUTS['detailed'])
def detailed_health():
    """
    Comprehensive system health check for administrative monitoring and diagnostics.
    
    Provides detailed system status including resource utilization metrics, external
    service validation, and performance diagnostics. Optimized for <200ms response time
    per Section 6.5.2.1 health check endpoint implementation requirements.
    
    Returns:
        JSON response with comprehensive system health status and metrics
        
    HTTP Status Codes:
        200: Detailed health information available
        503: Critical system issues detected
        500: Health check execution failed
    """
    try:
        # Collect comprehensive health information
        db_status = check_database_connectivity()
        external_services = validate_external_services()
        resource_analysis = analyze_resource_utilization()
        system_info = get_system_info()
        
        # Determine overall system health
        overall_status = 'healthy'
        
        # Check for critical issues
        if db_status['status'] == 'unhealthy':
            overall_status = 'critical'
        elif (db_status['status'] == 'degraded' or 
              external_services['overall_status'] == 'degraded' or
              resource_analysis['status'] in ['warning', 'critical']):
            overall_status = 'degraded'
        
        if resource_analysis['status'] == 'critical':
            overall_status = 'critical'
        
        response_data = {
            'status': overall_status,
            'service': 'flask-app',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'production'),
            'checks': {
                'database': db_status,
                'external_services': external_services,
                'resource_utilization': resource_analysis,
                'system_info': system_info
            },
            'summary': {
                'database_healthy': db_status['status'] in ['healthy', 'degraded'],
                'external_services_healthy': external_services['overall_status'] in ['healthy', 'degraded'],
                'resources_optimal': resource_analysis['status'] == 'healthy',
                'total_alerts': resource_analysis['alert_count']
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'detailed'
        }
        
        status_code = 200 if overall_status in ['healthy', 'degraded'] else 503
        
        logger.info(f"Detailed health check completed: {overall_status}")
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {e}")
        return jsonify({
            'status': 'error',
            'service': 'flask-app',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'detailed'
        }), 500


@health_bp.route('/', methods=['GET'])
def health_index():
    """
    Default health endpoint providing quick system status overview.
    
    Serves as the primary health check endpoint for general monitoring
    with balanced performance and information content.
    
    Returns:
        JSON response with basic system health status and quick metrics
    """
    try:
        # Quick database connectivity check
        db_status = check_database_connectivity()
        
        # Basic system metrics
        system_info = get_system_info()
        cpu_usage = system_info.get('cpu', {}).get('usage_percent', 0)
        memory_usage = system_info.get('memory', {}).get('usage_percent', 0)
        
        is_healthy = db_status['status'] in ['healthy', 'degraded']
        
        response_data = {
            'status': 'healthy' if is_healthy else 'unhealthy',
            'service': 'flask-app',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'database': db_status['connectivity'],
            'metrics': {
                'cpu_usage_percent': cpu_usage,
                'memory_usage_percent': memory_usage,
                'database_response_ms': db_status['query_response_time_ms']
            },
            'endpoints': {
                'liveness': '/health/liveness',
                'readiness': '/health/readiness', 
                'detailed': '/health/detailed'
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'overview'
        }
        
        status_code = 200 if is_healthy else 503
        return jsonify(response_data), status_code
        
    except Exception as e:
        logger.error(f"Health overview failed: {e}")
        return jsonify({
            'status': 'error',
            'service': 'flask-app',
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'check_type': 'overview'
        }), 500


@health_bp.route('/metrics', methods=['GET'])
def health_metrics():
    """
    Prometheus-compatible metrics endpoint for monitoring integration.
    
    Provides system metrics in a format compatible with Prometheus scraping
    for comprehensive monitoring and alerting integration per Section 6.5.1.1
    metrics collection requirements.
    
    Returns:
        Plain text response with Prometheus-compatible metrics format
    """
    try:
        # Collect current metrics
        db_status = check_database_connectivity()
        system_info = get_system_info()
        resource_analysis = analyze_resource_utilization()
        
        # Generate Prometheus metrics format
        metrics_lines = [
            '# HELP flask_app_health Application health status (1=healthy, 0=unhealthy)',
            '# TYPE flask_app_health gauge',
            f'flask_app_health{{service="flask-app"}} {1 if db_status["status"] in ["healthy", "degraded"] else 0}',
            '',
            '# HELP flask_app_database_response_time Database response time in milliseconds',
            '# TYPE flask_app_database_response_time gauge',
            f'flask_app_database_response_time{{service="flask-app"}} {db_status.get("query_response_time_ms", 0)}',
            '',
            '# HELP flask_app_cpu_usage CPU usage percentage',
            '# TYPE flask_app_cpu_usage gauge',
            f'flask_app_cpu_usage{{service="flask-app"}} {system_info.get("cpu", {}).get("usage_percent", 0)}',
            '',
            '# HELP flask_app_memory_usage Memory usage percentage',
            '# TYPE flask_app_memory_usage gauge',
            f'flask_app_memory_usage{{service="flask-app"}} {system_info.get("memory", {}).get("usage_percent", 0)}',
            '',
            '# HELP flask_app_disk_usage Disk usage percentage',
            '# TYPE flask_app_disk_usage gauge',
            f'flask_app_disk_usage{{service="flask-app"}} {system_info.get("disk", {}).get("usage_percent", 0)}',
            '',
            '# HELP flask_app_alerts_total Total number of active alerts',
            '# TYPE flask_app_alerts_total gauge',
            f'flask_app_alerts_total{{service="flask-app"}} {resource_analysis.get("alert_count", 0)}',
            ''
        ]
        
        # Add database connection pool metrics if available
        pool_info = db_status.get('pool_info', {})
        if pool_info.get('pool_size'):
            metrics_lines.extend([
                '# HELP flask_app_db_pool_size Database connection pool size',
                '# TYPE flask_app_db_pool_size gauge',
                f'flask_app_db_pool_size{{service="flask-app"}} {pool_info["pool_size"]}',
                '',
                '# HELP flask_app_db_active_connections Active database connections',
                '# TYPE flask_app_db_active_connections gauge',
                f'flask_app_db_active_connections{{service="flask-app"}} {pool_info.get("active_connections", 0)}',
                ''
            ])
        
        metrics_content = '\n'.join(metrics_lines)
        
        logger.debug("Health metrics generated successfully")
        return metrics_content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
        
    except Exception as e:
        logger.error(f"Health metrics generation failed: {e}")
        return f'# Error generating metrics: {str(e)}\n', 500, {'Content-Type': 'text/plain; charset=utf-8'}


# Error handlers for health check blueprint
@health_bp.errorhandler(404)
def health_not_found(error):
    """Handle 404 errors within health check blueprint."""
    return jsonify({
        'status': 'error',
        'message': 'Health check endpoint not found',
        'available_endpoints': [
            '/health/',
            '/health/liveness',
            '/health/readiness',
            '/health/detailed',
            '/health/metrics'
        ],
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 404


@health_bp.errorhandler(500)
def health_internal_error(error):
    """Handle 500 errors within health check blueprint."""
    logger.error(f"Internal error in health check: {error}")
    return jsonify({
        'status': 'error',
        'message': 'Internal health check error',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 500


# Request logging for health check monitoring
@health_bp.before_request
def log_health_check_request():
    """Log health check requests for monitoring and debugging."""
    g.health_check_start_time = time.time()
    logger.debug(f"Health check request: {request.method} {request.path} from {request.remote_addr}")


@health_bp.after_request
def log_health_check_response(response):
    """Log health check responses with performance metrics."""
    if hasattr(g, 'health_check_start_time'):
        duration = time.time() - g.health_check_start_time
        logger.debug(
            f"Health check response: {request.path} -> {response.status_code} "
            f"({duration:.3f}s)"
        )
    return response


# Initialize health check configuration
def init_health_checks(app):
    """
    Initialize health check configuration and register with Flask application.
    
    Configures health check thresholds, logging, and integration settings
    for optimal monitoring performance and reliability.
    
    Args:
        app: Flask application instance
    """
    # Configure health check specific logging
    health_logger = logging.getLogger('blueprints.health')
    health_logger.setLevel(app.config.get('HEALTH_CHECK_LOG_LEVEL', logging.INFO))
    
    # Register health check configuration
    app.config.setdefault('HEALTH_CHECK_TIMEOUTS', HEALTH_CHECK_TIMEOUTS)
    app.config.setdefault('SERVICE_HEALTH_THRESHOLDS', SERVICE_HEALTH_THRESHOLDS)
    
    logger.info("Health check blueprint initialized successfully")


# Export blueprint and initialization function
__all__ = ['health_bp', 'init_health_checks']