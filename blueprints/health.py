"""
Flask Health Check Blueprint

This module provides comprehensive system monitoring endpoints for application health validation,
database connectivity checks, and service availability reporting. The blueprint enables container
orchestration integration with Kubernetes liveness and readiness probes while supporting production
monitoring and alerting systems.

Key Features:
- Application health endpoint providing comprehensive system status per Section 6.1.5
- Database connectivity validation for operational monitoring per Section 5.2.4
- Container orchestration integration for Kubernetes deployment per Section 6.1.5
- Resource utilization metrics for performance monitoring per Section 6.1.5
- Docker HEALTHCHECK instruction support per Section 6.1.5

Health Check Endpoints:
- GET /health - Basic application health with database connectivity
- GET /health/liveness - Kubernetes liveness probe (minimal checks)
- GET /health/readiness - Kubernetes readiness probe (comprehensive checks)
- GET /health/detailed - Administrative monitoring with detailed metrics

Performance Requirements:
- Basic health check: <50ms response time
- Readiness probe: <100ms response time
- Detailed health check: <200ms response time
- Database connectivity validation within timeout limits

Dependencies:
- Flask 3.1.1: Blueprint registration and route handling
- Flask-SQLAlchemy 3.1.1: Database connectivity validation
- DatabaseManager: Health check utilities from models module
- Jinja2 templates: JSON response formatting and template inheritance
"""

import os
import sys
import time
import psutil
import platform
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, Union
from uuid import uuid4

# Core Flask imports
from flask import Blueprint, jsonify, render_template, request, g, current_app
from flask import __version__ as flask_version

# SQLAlchemy imports for database health checks
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError, OperationalError

# Database models and utilities
from models import db, DatabaseManager, DatabaseError

# Configure logging for health check operations
logger = logging.getLogger(__name__)

# Create health check blueprint with template and static folder configuration
health_bp = Blueprint(
    'health',
    __name__,
    url_prefix='/health',
    template_folder='../templates/health',
    static_folder='../static'
)


class HealthCheckError(Exception):
    """Custom exception for health check operations."""
    pass


class HealthCheckManager:
    """
    Comprehensive health check management utility for system monitoring.
    
    Provides health check coordination, performance metrics collection,
    and status reporting for container orchestration and monitoring systems.
    """
    
    @staticmethod
    def get_application_info() -> Dict[str, Any]:
        """
        Retrieve comprehensive application information and metadata.
        
        Returns:
            Dict containing application details and system information
        """
        try:
            # Get process and system information
            process = psutil.Process()
            system_info = {
                'hostname': platform.node(),
                'process_id': os.getpid(),
                'worker_id': os.environ.get('WORKER_ID', 'main'),
                'container_id': os.environ.get('HOSTNAME', '')[:12],  # Docker container ID
                'python_version': platform.python_version(),
                'flask_version': flask_version,
                'platform': platform.system(),
                'architecture': platform.machine()
            }
            
            # Calculate application uptime
            app_start_time = getattr(current_app, '_start_time', time.time())
            uptime_seconds = int(time.time() - app_start_time)
            
            # Get environment configuration
            app_info = {
                'name': current_app.config.get('APP_NAME', 'flask-application'),
                'version': current_app.config.get('APP_VERSION', '1.0.0'),
                'environment': current_app.config.get('FLASK_ENV', 'development'),
                'debug_mode': current_app.debug,
                'uptime_seconds': uptime_seconds,
                'instance_id': os.environ.get('INSTANCE_ID', platform.node())
            }
            
            return {
                'application': app_info,
                'system': system_info,
                'process': {
                    'pid': process.pid,
                    'ppid': process.ppid(),
                    'create_time': process.create_time(),
                    'num_threads': process.num_threads()
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting application info: {str(e)}")
            return {
                'application': {'name': 'flask-application', 'version': '1.0.0'},
                'system': {'hostname': 'unknown'},
                'process': {'pid': os.getpid()}
            }
    
    @staticmethod
    def get_performance_metrics() -> Dict[str, Union[float, int]]:
        """
        Collect system performance and resource utilization metrics.
        
        Returns:
            Dict containing performance metrics for monitoring
        """
        try:
            # Get process-specific metrics
            process = psutil.Process()
            memory_info = process.memory_info()
            cpu_percent = process.cpu_percent(interval=0.1)
            
            # Get system-wide metrics
            system_memory = psutil.virtual_memory()
            system_cpu = psutil.cpu_percent(interval=0.1)
            disk_usage = psutil.disk_usage('/')
            
            # Calculate memory usage in MB
            memory_usage_mb = memory_info.rss / (1024 * 1024)
            system_memory_usage_mb = system_memory.used / (1024 * 1024)
            
            return {
                'process_memory_mb': round(memory_usage_mb, 2),
                'process_cpu_percent': round(cpu_percent, 2),
                'system_memory_mb': round(system_memory_usage_mb, 2),
                'system_memory_percent': round(system_memory.percent, 2),
                'system_cpu_percent': round(system_cpu, 2),
                'disk_usage_percent': round(disk_usage.percent, 2),
                'disk_free_gb': round(disk_usage.free / (1024**3), 2),
                'load_average': os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0.0
            }
            
        except Exception as e:
            logger.error(f"Error collecting performance metrics: {str(e)}")
            return {
                'process_memory_mb': 0.0,
                'process_cpu_percent': 0.0,
                'system_memory_percent': 0.0,
                'system_cpu_percent': 0.0,
                'disk_usage_percent': 0.0,
                'error': str(e)
            }
    
    @staticmethod
    def check_database_connectivity() -> Dict[str, Any]:
        """
        Perform comprehensive database connectivity and health validation.
        
        Returns:
            Dict containing database health status and connection metrics
        """
        database_health = {
            'status': 'unknown',
            'accessible': False,
            'response_time_ms': 0,
            'pool_status': {},
            'version_info': '',
            'ssl_enabled': False,
            'errors': []
        }
        
        start_time = time.time()
        
        try:
            # Use DatabaseManager for comprehensive health check
            health_result = DatabaseManager.check_database_health()
            
            # Calculate response time
            response_time = (time.time() - start_time) * 1000
            database_health.update({
                'status': health_result.get('status', 'unknown'),
                'accessible': health_result.get('database_accessible', False),
                'response_time_ms': round(response_time, 2),
                'pool_status': health_result.get('metrics', {}),
                'ssl_enabled': health_result.get('ssl_enabled', False),
                'errors': health_result.get('errors', [])
            })
            
            # Additional database version check
            if health_result.get('database_accessible'):
                try:
                    version_result = db.session.execute(text('SELECT version()')).scalar()
                    database_health['version_info'] = version_result
                except Exception as e:
                    database_health['errors'].append(f"Version check failed: {str(e)}")
            
            # Validate connection pool health
            pool_metrics = DatabaseManager.get_connection_pool_status()
            if pool_metrics:
                database_health['pool_status'] = pool_metrics
                
                # Check for pool health issues
                invalid_connections = pool_metrics.get('invalid', 0)
                total_connections = pool_metrics.get('total_connections', 0)
                
                if invalid_connections > 0:
                    database_health['errors'].append(f"Pool has {invalid_connections} invalid connections")
                
                if total_connections == 0:
                    database_health['errors'].append("No active database connections")
            
        except DatabaseError as e:
            database_health.update({
                'status': 'unhealthy',
                'accessible': False,
                'response_time_ms': round((time.time() - start_time) * 1000, 2),
                'errors': [f"Database error: {str(e)}"]
            })
            logger.error(f"Database health check failed: {str(e)}")
            
        except Exception as e:
            database_health.update({
                'status': 'error',
                'accessible': False,
                'response_time_ms': round((time.time() - start_time) * 1000, 2),
                'errors': [f"Unexpected error: {str(e)}"]
            })
            logger.error(f"Unexpected database health check error: {str(e)}")
        
        return database_health
    
    @staticmethod
    def check_external_services() -> Dict[str, Any]:
        """
        Validate external service connectivity and availability.
        
        Returns:
            Dict containing external service health status
        """
        services_health = {
            'auth0': {'status': 'unknown', 'response_time_ms': 0},
            'monitoring': {'status': 'healthy', 'response_time_ms': 0},
            'overall_status': 'unknown'
        }
        
        # Check Auth0 connectivity (if configured)
        auth0_domain = current_app.config.get('AUTH0_DOMAIN')
        if auth0_domain:
            start_time = time.time()
            try:
                # Simple connectivity check to Auth0 domain
                import requests
                response = requests.head(f"https://{auth0_domain}/.well-known/jwks.json", timeout=5)
                response_time = (time.time() - start_time) * 1000
                
                if response.status_code == 200:
                    services_health['auth0'] = {
                        'status': 'healthy',
                        'response_time_ms': round(response_time, 2)
                    }
                else:
                    services_health['auth0'] = {
                        'status': 'degraded',
                        'response_time_ms': round(response_time, 2),
                        'error': f"HTTP {response.status_code}"
                    }
                    
            except Exception as e:
                services_health['auth0'] = {
                    'status': 'unhealthy',
                    'response_time_ms': round((time.time() - start_time) * 1000, 2),
                    'error': str(e)
                }
        else:
            services_health['auth0'] = {'status': 'not_configured', 'response_time_ms': 0}
        
        # Determine overall service status
        service_statuses = [svc['status'] for svc in services_health.values() if isinstance(svc, dict)]
        if 'unhealthy' in service_statuses:
            services_health['overall_status'] = 'unhealthy'
        elif 'degraded' in service_statuses:
            services_health['overall_status'] = 'degraded'
        else:
            services_health['overall_status'] = 'healthy'
        
        return services_health
    
    @staticmethod
    def determine_overall_health(database_health: Dict[str, Any], 
                               services_health: Dict[str, Any], 
                               performance_metrics: Dict[str, Any]) -> Tuple[str, int]:
        """
        Determine overall application health status based on component checks.
        
        Args:
            database_health: Database connectivity results
            services_health: External services connectivity results
            performance_metrics: System performance metrics
            
        Returns:
            Tuple of (status_string, http_status_code)
        """
        # Check database health
        db_healthy = database_health.get('status') == 'healthy'
        db_accessible = database_health.get('accessible', False)
        
        # Check services health
        services_overall = services_health.get('overall_status', 'unknown')
        
        # Check performance thresholds
        cpu_percent = performance_metrics.get('process_cpu_percent', 0)
        memory_percent = performance_metrics.get('system_memory_percent', 0)
        disk_percent = performance_metrics.get('disk_usage_percent', 0)
        
        # Define performance thresholds
        performance_healthy = (
            cpu_percent < 80 and
            memory_percent < 85 and
            disk_percent < 90
        )
        
        # Determine overall status
        if not db_accessible:
            return 'unhealthy', 503
        elif not db_healthy:
            return 'degraded', 200
        elif services_overall == 'unhealthy':
            return 'degraded', 200
        elif not performance_healthy:
            return 'warning', 200
        elif services_overall in ['degraded', 'warning']:
            return 'warning', 200
        else:
            return 'healthy', 200


def create_health_context(check_type: str = 'basic', 
                         start_time: Optional[float] = None) -> Dict[str, Any]:
    """
    Create comprehensive health check context for template rendering.
    
    Args:
        check_type: Type of health check being performed
        start_time: Start time for duration calculation
        
    Returns:
        Dict containing all health check data for template rendering
    """
    if start_time is None:
        start_time = time.time()
    
    # Set request ID for tracing
    if not hasattr(g, 'request_id'):
        g.request_id = str(uuid4())
    
    # Get application information
    app_info = HealthCheckManager.get_application_info()
    
    # Get performance metrics
    performance_metrics = HealthCheckManager.get_performance_metrics()
    
    # Get database health (for readiness and detailed checks)
    database_health = {}
    services_health = {}
    
    if check_type in ['readiness', 'detailed', 'basic']:
        database_health = HealthCheckManager.check_database_connectivity()
    
    # Get external services health (for detailed checks)
    if check_type == 'detailed':
        services_health = HealthCheckManager.check_external_services()
    
    # Determine overall health status
    overall_status, http_status = HealthCheckManager.determine_overall_health(
        database_health, services_health, performance_metrics
    )
    
    # Calculate check duration
    check_duration_ms = round((time.time() - start_time) * 1000, 2)
    
    # Create comprehensive context
    context = {
        # Basic application info
        'health_status': overall_status,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'hostname': app_info['system']['hostname'],
        'instance_id': app_info['application']['instance_id'],
        'uptime_seconds': app_info['application']['uptime_seconds'],
        'process_id': app_info['system']['process_id'],
        'worker_id': app_info['system']['worker_id'],
        'container_id': app_info['system']['container_id'],
        
        # Performance metrics
        'response_time_ms': check_duration_ms,
        'memory_usage_mb': performance_metrics.get('process_memory_mb', 0),
        'cpu_usage_percent': performance_metrics.get('process_cpu_percent', 0),
        
        # Application status
        'application_status': 'healthy' if overall_status in ['healthy', 'warning'] else 'degraded',
        
        # Version information
        'flask_version': flask_version,
        'python_version': app_info['system']['python_version'],
        
        # Check metadata
        'check_duration_ms': check_duration_ms,
        'orchestration_platform': os.environ.get('ORCHESTRATION_PLATFORM', 'docker'),
        
        # HTTP status for response
        'http_status': http_status,
        
        # Request context
        'request_url': request.url if request else '/health',
        
        # Additional data for detailed checks
        'database_health': database_health,
        'services_health': services_health,
        'performance_metrics': performance_metrics,
        'app_info': app_info
    }
    
    return context


@health_bp.route('/', methods=['GET'])
def health_check():
    """
    Basic application health check endpoint.
    
    Provides essential health status with database connectivity validation.
    Optimized for load balancer health checks and basic monitoring.
    
    Performance Target: <50ms response time
    
    Returns:
        JSON response with basic health status and HTTP status code
    """
    start_time = time.time()
    
    try:
        # Create health context with basic checks
        context = create_health_context('basic', start_time)
        
        # Create simplified response for basic health check
        response_data = {
            'status': context['health_status'],
            'timestamp': context['timestamp'],
            'service': {
                'name': current_app.config.get('APP_NAME', 'flask-application'),
                'version': current_app.config.get('APP_VERSION', '1.0.0'),
                'uptime_seconds': context['uptime_seconds']
            },
            'database': {
                'accessible': context['database_health'].get('accessible', False),
                'response_time_ms': context['database_health'].get('response_time_ms', 0)
            },
            'performance': {
                'response_time_ms': context['response_time_ms'],
                'memory_usage_mb': context['memory_usage_mb']
            },
            'metadata': {
                'check_type': 'basic',
                'check_duration_ms': context['check_duration_ms']
            }
        }
        
        return jsonify(response_data), context['http_status']
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        error_response = {
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'metadata': {
                'check_type': 'basic',
                'check_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
        }
        return jsonify(error_response), 500


@health_bp.route('/liveness', methods=['GET'])
def liveness_probe():
    """
    Kubernetes liveness probe endpoint.
    
    Minimal health check for container orchestration liveness validation.
    Validates basic application responsiveness without external dependencies.
    
    Performance Target: <50ms response time
    
    Returns:
        JSON response indicating application liveness status
    """
    start_time = time.time()
    
    try:
        # Minimal check for application responsiveness
        context = {
            'health_status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'hostname': platform.node(),
            'process_id': os.getpid(),
            'uptime_seconds': int(time.time() - getattr(current_app, '_start_time', time.time())),
            'response_time_ms': round((time.time() - start_time) * 1000, 2),
            'flask_version': flask_version,
            'python_version': platform.python_version(),
            'check_duration_ms': round((time.time() - start_time) * 1000, 2)
        }
        
        # Render liveness template
        try:
            response_json = render_template('liveness.json', **context)
            return current_app.response_class(
                response_json,
                status=200,
                mimetype='application/json'
            )
        except Exception:
            # Fallback to direct JSON response
            response_data = {
                'status': 'healthy',
                'timestamp': context['timestamp'],
                'service': {
                    'name': current_app.config.get('APP_NAME', 'flask-application'),
                    'uptime_seconds': context['uptime_seconds']
                },
                'metadata': {
                    'check_type': 'liveness',
                    'check_duration_ms': context['check_duration_ms']
                }
            }
            return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Liveness probe failed: {str(e)}")
        error_response = {
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'metadata': {
                'check_type': 'liveness',
                'check_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
        }
        return jsonify(error_response), 500


@health_bp.route('/readiness', methods=['GET'])
def readiness_probe():
    """
    Kubernetes readiness probe endpoint.
    
    Comprehensive readiness validation including database connectivity
    and external service availability. Used for deployment health validation.
    
    Performance Target: <100ms response time
    
    Returns:
        JSON response with comprehensive readiness status
    """
    start_time = time.time()
    
    try:
        # Create comprehensive health context for readiness
        context = create_health_context('readiness', start_time)
        
        # Determine readiness based on critical dependencies
        database_ready = context['database_health'].get('accessible', False)
        
        # Override status for readiness - must have database connectivity
        if not database_ready:
            context['health_status'] = 'not_ready'
            context['http_status'] = 503
        elif context['health_status'] == 'healthy':
            context['health_status'] = 'ready'
        
        # Render readiness template
        try:
            response_json = render_template('readiness.json', **context)
            return current_app.response_class(
                response_json,
                status=context['http_status'],
                mimetype='application/json'
            )
        except Exception:
            # Fallback to direct JSON response
            response_data = {
                'status': context['health_status'],
                'timestamp': context['timestamp'],
                'service': {
                    'name': current_app.config.get('APP_NAME', 'flask-application'),
                    'version': current_app.config.get('APP_VERSION', '1.0.0'),
                    'uptime_seconds': context['uptime_seconds']
                },
                'database': {
                    'accessible': database_ready,
                    'response_time_ms': context['database_health'].get('response_time_ms', 0),
                    'status': context['database_health'].get('status', 'unknown')
                },
                'metadata': {
                    'check_type': 'readiness',
                    'check_duration_ms': context['check_duration_ms']
                }
            }
            return jsonify(response_data), context['http_status']
        
    except Exception as e:
        logger.error(f"Readiness probe failed: {str(e)}")
        error_response = {
            'status': 'not_ready',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'metadata': {
                'check_type': 'readiness',
                'check_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
        }
        return jsonify(error_response), 503


@health_bp.route('/detailed', methods=['GET'])
def detailed_health_check():
    """
    Detailed administrative health check endpoint.
    
    Comprehensive system monitoring with detailed metrics collection,
    performance analysis, and administrative monitoring information.
    
    Performance Target: <200ms response time
    
    Returns:
        JSON response with comprehensive system health details
    """
    start_time = time.time()
    
    try:
        # Create comprehensive health context with all checks
        context = create_health_context('detailed', start_time)
        
        # Render detailed health template
        try:
            response_json = render_template('detailed.json', **context)
            return current_app.response_class(
                response_json,
                status=context['http_status'],
                mimetype='application/json'
            )
        except Exception as template_error:
            logger.warning(f"Template rendering failed, using fallback: {str(template_error)}")
            
            # Comprehensive fallback response
            response_data = {
                'status': context['health_status'],
                'timestamp': context['timestamp'],
                'environment': current_app.config.get('FLASK_ENV', 'development'),
                'version': current_app.config.get('APP_VERSION', '1.0.0'),
                'service': {
                    'name': current_app.config.get('APP_NAME', 'flask-application'),
                    'instance_id': context['instance_id'],
                    'uptime_seconds': context['uptime_seconds'],
                    'request_id': getattr(g, 'request_id', '')
                },
                'system': {
                    'hostname': context['hostname'],
                    'process_id': context['process_id'],
                    'worker_id': context['worker_id'],
                    'container_id': context['container_id']
                },
                'performance': {
                    'response_time_ms': context['response_time_ms'],
                    'memory_usage_mb': context['memory_usage_mb'],
                    'cpu_usage_percent': context['cpu_usage_percent'],
                    'detailed_metrics': context['performance_metrics']
                },
                'checks': {
                    'application': {
                        'status': context['application_status'],
                        'details': 'Flask application running normally'
                    },
                    'database': context['database_health'],
                    'external_services': context['services_health']
                },
                'metadata': {
                    'check_type': 'detailed',
                    'check_duration_ms': context['check_duration_ms'],
                    'flask_version': context['flask_version'],
                    'python_version': context['python_version'],
                    'monitoring': {
                        'alb_compatible': True,
                        'ec2_compatible': True,
                        'container_orchestration': context['orchestration_platform']
                    }
                },
                'links': {
                    'self': context['request_url'],
                    'related': {
                        'liveness': '/health/liveness',
                        'readiness': '/health/readiness',
                        'basic': '/health',
                        'metrics': '/metrics'
                    }
                }
            }
            
            return jsonify(response_data), context['http_status']
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {str(e)}")
        error_response = {
            'status': 'error',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'error': str(e),
            'metadata': {
                'check_type': 'detailed',
                'check_duration_ms': round((time.time() - start_time) * 1000, 2)
            }
        }
        return jsonify(error_response), 500


@health_bp.before_app_request
def before_health_check():
    """
    Pre-request processing for health check endpoints.
    
    Sets up request tracking and performance monitoring for health endpoints.
    """
    if request.endpoint and 'health' in request.endpoint:
        # Set request start time for performance tracking
        g.request_start_time = time.time()
        
        # Generate request ID for tracing
        g.request_id = str(uuid4())
        
        # Log health check request (debug level to avoid log spam)
        logger.debug(f"Health check request: {request.endpoint} from {request.remote_addr}")


@health_bp.after_app_request
def after_health_check(response):
    """
    Post-request processing for health check endpoints.
    
    Logs performance metrics and request completion for monitoring.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified response object
    """
    if request.endpoint and 'health' in request.endpoint:
        # Calculate request duration
        if hasattr(g, 'request_start_time'):
            duration_ms = round((time.time() - g.request_start_time) * 1000, 2)
            
            # Log performance metrics (debug level)
            logger.debug(
                f"Health check completed: {request.endpoint} "
                f"duration={duration_ms}ms status={response.status_code}"
            )
            
            # Add performance headers for monitoring
            response.headers['X-Response-Time'] = f"{duration_ms}ms"
            response.headers['X-Request-ID'] = getattr(g, 'request_id', '')
        
        # Add caching headers for health endpoints
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        # Add CORS headers for cross-origin monitoring
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET'
        
    return response


@health_bp.errorhandler(Exception)
def handle_health_check_error(error):
    """
    Global error handler for health check blueprint.
    
    Ensures health check endpoints always return proper JSON responses
    even in case of unexpected errors.
    
    Args:
        error: Exception that occurred
        
    Returns:
        JSON error response with proper HTTP status
    """
    logger.error(f"Health check error: {str(error)}", exc_info=True)
    
    error_response = {
        'status': 'error',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'error': str(error),
        'metadata': {
            'check_type': 'error',
            'endpoint': request.endpoint or 'unknown'
        }
    }
    
    # Determine appropriate HTTP status based on error type
    if isinstance(error, DatabaseError):
        status_code = 503
    elif isinstance(error, HealthCheckError):
        status_code = 500
    else:
        status_code = 500
    
    return jsonify(error_response), status_code


# Export blueprint for application registration
__all__ = ['health_bp', 'HealthCheckManager', 'HealthCheckError']


def register_health_blueprint(app):
    """
    Register health check blueprint with Flask application.
    
    This function provides a convenient way to register the health blueprint
    with proper configuration and initialization.
    
    Args:
        app: Flask application instance
    """
    # Set application start time for uptime calculation
    if not hasattr(app, '_start_time'):
        app._start_time = time.time()
    
    # Register the blueprint
    app.register_blueprint(health_bp)
    
    # Log successful registration
    app.logger.info("Health check blueprint registered successfully")
    app.logger.info("Available health endpoints: /health, /health/liveness, /health/readiness, /health/detailed")


# Initialize logging for the health module
if __name__ != '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )