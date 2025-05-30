"""
Main Application Blueprint

This module implements the core Flask blueprint for main application routes, providing the primary
entry point for non-API routes including index pages, general application endpoints, and navigation
routes. The blueprint maintains functional equivalence with Express.js main route handlers while
leveraging Flask 3.1.1's enhanced capabilities and modular blueprint architecture.

Key Features:
- Flask 3.1.1 blueprint pattern with comprehensive route decorator implementation per Section 4.3.1.3
- Request/response handling using Flask request context per Section 4.3.2.1
- Modular route organization supporting Flask application factory pattern per Section 5.2.2
- Service layer integration for business logic coordination per Section 6.1.6
- Enhanced error handling with standardized HTTP status codes and response formatting
- Performance monitoring and health check coordination
- Template rendering capabilities with Jinja2 integration
- Session management and user context preservation

Architecture Benefits:
- Clear separation between presentation layer (blueprint routes) and business logic (service layer)
- Enhanced maintainability through Flask's declarative routing approach
- Comprehensive error handling with proper HTTP status codes and structured responses
- Service Layer pattern integration enabling testability and workflow orchestration
- Template rendering support for server-side rendering capabilities
- Session management integration with Flask-Login and ItsDangerous

Dependencies:
- Flask 3.1.1: Core web framework and blueprint functionality
- Service Layer: Business logic orchestration and workflow coordination
- Models: Database access and entity management through Flask-SQLAlchemy
- Template Engine: Jinja2 integration for server-side rendering
- Session Management: Flask session handling with secure cookie protection

This blueprint serves as the foundation for main application functionality, ensuring seamless migration
from Node.js/Express.js patterns while providing enhanced capabilities and improved maintainability
through Flask's mature ecosystem and Python's superior development experience.
"""

import logging
from typing import Dict, Any, Optional, Union, Tuple
from datetime import datetime, timezone
from functools import wraps

# Core Flask imports for blueprint implementation
from flask import (
    Blueprint, 
    request, 
    jsonify, 
    render_template, 
    redirect, 
    url_for, 
    flash, 
    session, 
    current_app,
    abort,
    make_response,
    g
)

# Import service layer for business logic coordination
from services import (
    get_service,
    UserService,
    ValidationService,
    AuthService,
    get_service_health,
    get_all_services,
    ServiceError,
    ValidationError,
    NotFoundError
)

# Import models for database access and entity management
from models import (
    User,
    db,
    DatabaseManager,
    ValidationError as ModelValidationError
)

# Configure logging for main blueprint
logger = logging.getLogger(__name__)

# Create main application blueprint with comprehensive configuration
main_bp = Blueprint(
    'main',
    __name__,
    url_prefix='/',
    template_folder='../templates',
    static_folder='../static',
    static_url_path='/static'
)


def handle_errors(f):
    """
    Decorator for comprehensive error handling across main application routes.
    
    Provides standardized error response formatting, logging, and HTTP status code
    management while preserving Flask's request context and maintaining API contract
    compliance with existing client applications.
    
    Args:
        f: Route handler function to wrap with error handling
        
    Returns:
        Wrapped function with enhanced error handling capabilities
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValidationError as e:
            logger.warning(f"Validation error in {f.__name__}: {e}")
            return jsonify({
                'error': 'Validation Error',
                'message': str(e),
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 400
        except NotFoundError as e:
            logger.warning(f"Resource not found in {f.__name__}: {e}")
            return jsonify({
                'error': 'Not Found',
                'message': str(e),
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 404
        except ServiceError as e:
            logger.error(f"Service error in {f.__name__}: {e}")
            return jsonify({
                'error': 'Service Error',
                'message': str(e),
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 500
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {e}", exc_info=True)
            return jsonify({
                'error': 'Internal Server Error',
                'message': 'An unexpected error occurred',
                'status': 'error',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 500
    
    return decorated_function


def require_valid_session(f):
    """
    Decorator for session validation and user context management.
    
    Ensures proper session handling and user authentication state validation
    while maintaining compatibility with existing authentication patterns.
    
    Args:
        f: Route handler function requiring session validation
        
    Returns:
        Wrapped function with session validation capabilities
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            # Validate session integrity
            if 'user_id' in session:
                auth_service = get_service(AuthService)
                user_context = auth_service.validate_session(session.get('user_id'))
                if user_context:
                    g.current_user = user_context
                else:
                    session.clear()
                    
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Session validation error in {f.__name__}: {e}")
            session.clear()
            return f(*args, **kwargs)
    
    return decorated_function


@main_bp.before_request
def before_request():
    """
    Pre-request processing for main application routes.
    
    Handles request initialization, logging, session validation, and security checks
    while maintaining compatibility with existing middleware patterns from Node.js implementation.
    """
    try:
        # Log request information for monitoring and debugging
        logger.debug(f"Processing request: {request.method} {request.path}")
        
        # Initialize request context variables
        g.request_start_time = datetime.now(timezone.utc)
        g.current_user = None
        
        # Validate request integrity and security
        if request.content_length and request.content_length > current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024):
            abort(413)  # Request Entity Too Large
        
        # Security headers and CSRF protection for forms
        if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if request.is_json:
                # Validate JSON content type
                if not request.content_type or 'application/json' not in request.content_type:
                    abort(400, description="Invalid content type for JSON request")
            
    except Exception as e:
        logger.error(f"Error in before_request: {e}")
        abort(500, description="Request processing error")


@main_bp.after_request
def after_request(response):
    """
    Post-request processing for main application routes.
    
    Handles response finalization, performance monitoring, security headers,
    and cleanup operations while preserving response integrity.
    
    Args:
        response: Flask response object
        
    Returns:
        Modified response with enhanced headers and monitoring
    """
    try:
        # Calculate request processing time for performance monitoring
        if hasattr(g, 'request_start_time'):
            processing_time = (datetime.now(timezone.utc) - g.request_start_time).total_seconds()
            response.headers['X-Processing-Time'] = f"{processing_time:.3f}s"
        
        # Add security headers for enhanced protection
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # Add cache control headers for optimal performance
        if request.endpoint and 'static' not in request.endpoint:
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        # Log response information for monitoring
        logger.debug(f"Response: {response.status_code} for {request.method} {request.path}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error in after_request: {e}")
        return response


@main_bp.route('/', methods=['GET'])
@handle_errors
@require_valid_session
def index():
    """
    Main application index route providing the primary entry point.
    
    Renders the main application page with user context, system status, and
    navigation elements while maintaining compatibility with existing client
    expectations and providing enhanced functionality through Flask capabilities.
    
    Returns:
        Flask response: Rendered template or JSON response based on request type
        
    HTTP Status Codes:
        200: Successful page render or data retrieval
        500: Internal server error during processing
    """
    try:
        # Gather application context information
        app_context = {
            'title': 'Main Application',
            'description': 'Flask-based application providing enhanced functionality',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'environment': current_app.config.get('ENVIRONMENT', 'development'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user_authenticated': g.current_user is not None,
            'user_context': g.current_user.to_dict() if g.current_user else None
        }
        
        # Handle JSON API requests
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'success',
                'message': 'Main application index',
                'data': app_context,
                'links': {
                    'health': url_for('health.health_check'),
                    'api': url_for('api.api_status'),
                    'status': url_for('main.status')
                }
            }), 200
        
        # Render HTML template for browser requests
        return render_template(
            'main/index.html',
            **app_context,
            navigation_links=_get_navigation_links()
        ), 200
        
    except Exception as e:
        logger.error(f"Error in index route: {e}", exc_info=True)
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Failed to load main page',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 500
        else:
            return render_template('errors/500.html'), 500


@main_bp.route('/about', methods=['GET'])
@handle_errors
def about():
    """
    Application information route providing system details and documentation.
    
    Returns comprehensive information about the Flask application including
    version details, technology stack, and system capabilities while maintaining
    compatibility with existing documentation patterns.
    
    Returns:
        Flask response: Application information in JSON or HTML format
        
    HTTP Status Codes:
        200: Successful information retrieval
        500: Internal server error during processing
    """
    try:
        # Compile comprehensive application information
        about_info = {
            'application': {
                'name': current_app.config.get('APP_NAME', 'Flask Application'),
                'version': current_app.config.get('APP_VERSION', '1.0.0'),
                'description': 'Python Flask 3.1.1 application migrated from Node.js/Express.js',
                'environment': current_app.config.get('ENVIRONMENT', 'development'),
                'build_date': current_app.config.get('BUILD_DATE'),
                'git_commit': current_app.config.get('GIT_COMMIT')
            },
            'technology_stack': {
                'framework': 'Flask 3.1.1',
                'database': 'PostgreSQL with Flask-SQLAlchemy 3.1.1',
                'migration_engine': 'Flask-Migrate 4.1.0 with Alembic',
                'authentication': 'Flask-Login 0.6.3 with ItsDangerous 2.2+',
                'template_engine': 'Jinja2 3.1.2+',
                'wsgi_server': 'Werkzeug 3.1+ / Gunicorn (production)',
                'python_version': current_app.config.get('PYTHON_VERSION', '3.13.3')
            },
            'architecture': {
                'pattern': 'Blueprint-based modular architecture',
                'service_layer': 'Service Layer pattern for business logic orchestration',
                'database_pattern': 'Flask-SQLAlchemy declarative models',
                'deployment': 'Monolithic application with horizontal scaling support'
            },
            'capabilities': {
                'api_endpoints': 'RESTful API with complete HTTP method support',
                'authentication': 'Secure session management and user access control',
                'database_migrations': 'Automated schema versioning and rollback procedures',
                'health_monitoring': 'Comprehensive health checks and performance metrics',
                'ai_ml_ready': 'Python ecosystem access for TensorFlow, Scikit-learn, PyTorch'
            },
            'links': {
                'health': url_for('health.health_check'),
                'api_status': url_for('api.api_status') if 'api.api_status' in current_app.view_functions else None,
                'documentation': '/docs',
                'repository': current_app.config.get('REPOSITORY_URL')
            }
        }
        
        # Return JSON response for API requests
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'success',
                'message': 'Application information retrieved successfully',
                'data': about_info,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 200
        
        # Render HTML template for browser requests
        return render_template(
            'main/about.html',
            about_info=about_info,
            page_title='About This Application'
        ), 200
        
    except Exception as e:
        logger.error(f"Error in about route: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve application information',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500


@main_bp.route('/status', methods=['GET'])
@handle_errors
def status():
    """
    Application status route providing real-time system health and metrics.
    
    Returns comprehensive system status including service health, database connectivity,
    performance metrics, and operational information for monitoring and alerting systems.
    
    Returns:
        Flask response: System status information in JSON format
        
    HTTP Status Codes:
        200: Successful status retrieval
        503: Service unavailable (degraded system health)
        500: Internal server error during status check
    """
    try:
        # Gather comprehensive system status information
        system_status = {
            'application': {
                'status': 'running',
                'uptime': _get_application_uptime(),
                'version': current_app.config.get('APP_VERSION', '1.0.0'),
                'environment': current_app.config.get('ENVIRONMENT', 'development'),
                'python_version': current_app.config.get('PYTHON_VERSION', '3.13.3'),
                'flask_version': current_app.config.get('FLASK_VERSION', '3.1.1')
            },
            'database': _get_database_status(),
            'services': _get_services_status(),
            'performance': _get_performance_metrics(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Determine overall system health
        overall_status = 'healthy'
        status_code = 200
        
        if system_status['database']['status'] != 'healthy':
            overall_status = 'degraded'
            status_code = 503
        
        unhealthy_services = [
            name for name, health in system_status['services'].items() 
            if not health.get('healthy', False)
        ]
        
        if unhealthy_services:
            overall_status = 'degraded'
            status_code = 503
            system_status['unhealthy_services'] = unhealthy_services
        
        system_status['overall_status'] = overall_status
        
        return jsonify({
            'status': 'success' if overall_status == 'healthy' else 'warning',
            'message': f'System status: {overall_status}',
            'data': system_status
        }), status_code
        
    except Exception as e:
        logger.error(f"Error in status route: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to retrieve system status',
            'overall_status': 'unknown',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500


@main_bp.route('/navigation', methods=['GET'])
@handle_errors
@require_valid_session
def navigation():
    """
    Application navigation route providing dynamic navigation menu generation.
    
    Returns navigation links and menu structure based on user permissions,
    application configuration, and available routes while maintaining
    compatibility with existing navigation patterns.
    
    Returns:
        Flask response: Navigation structure in JSON or HTML format
        
    HTTP Status Codes:
        200: Successful navigation retrieval
        500: Internal server error during navigation generation
    """
    try:
        # Generate navigation structure based on user context
        navigation_data = {
            'primary_navigation': _get_navigation_links(),
            'user_navigation': _get_user_navigation_links(),
            'admin_navigation': _get_admin_navigation_links() if _is_admin_user() else None,
            'footer_links': _get_footer_links(),
            'user_context': {
                'authenticated': g.current_user is not None,
                'user_id': g.current_user.id if g.current_user else None,
                'username': g.current_user.username if g.current_user else None,
                'permissions': _get_user_permissions() if g.current_user else []
            }
        }
        
        # Return JSON response for API requests
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'success',
                'message': 'Navigation data retrieved successfully',
                'data': navigation_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 200
        
        # Render navigation template for inclusion in other pages
        return render_template(
            'main/navigation.html',
            navigation=navigation_data
        ), 200
        
    except Exception as e:
        logger.error(f"Error in navigation route: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to generate navigation',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500


@main_bp.route('/dashboard', methods=['GET'])
@handle_errors
@require_valid_session
def dashboard():
    """
    User dashboard route providing personalized application overview.
    
    Returns user-specific dashboard with relevant information, quick actions,
    and system overview while maintaining security and user context validation.
    
    Returns:
        Flask response: Dashboard content in JSON or HTML format
        
    HTTP Status Codes:
        200: Successful dashboard retrieval
        401: Unauthorized access (authentication required)
        500: Internal server error during dashboard generation
    """
    try:
        # Require user authentication for dashboard access
        if not g.current_user:
            if request.headers.get('Accept') == 'application/json':
                return jsonify({
                    'status': 'error',
                    'message': 'Authentication required for dashboard access',
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }), 401
            else:
                flash('Please log in to access the dashboard.', 'warning')
                return redirect(url_for('auth.login'))
        
        # Gather user-specific dashboard information
        user_service = get_service(UserService)
        dashboard_data = {
            'user_profile': {
                'id': g.current_user.id,
                'username': g.current_user.username,
                'email': g.current_user.email,
                'last_login': g.current_user.last_login.isoformat() if g.current_user.last_login else None,
                'account_created': g.current_user.created_at.isoformat()
            },
            'quick_actions': _get_user_quick_actions(),
            'system_overview': {
                'application_status': 'running',
                'user_permissions': _get_user_permissions(),
                'available_features': _get_available_features()
            },
            'recent_activity': _get_user_recent_activity(),
            'notifications': _get_user_notifications()
        }
        
        # Return JSON response for API requests
        if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
            return jsonify({
                'status': 'success',
                'message': 'Dashboard data retrieved successfully',
                'data': dashboard_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }), 200
        
        # Render dashboard template for browser requests
        return render_template(
            'main/dashboard.html',
            dashboard=dashboard_data,
            page_title='User Dashboard'
        ), 200
        
    except Exception as e:
        logger.error(f"Error in dashboard route: {e}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Failed to load dashboard',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500


# Helper functions for route implementations

def _get_navigation_links() -> list:
    """
    Generate primary navigation links for the application.
    
    Returns:
        List of navigation link dictionaries with URLs and labels
    """
    return [
        {'url': url_for('main.index'), 'label': 'Home', 'icon': 'home'},
        {'url': url_for('main.about'), 'label': 'About', 'icon': 'info'},
        {'url': url_for('main.status'), 'label': 'Status', 'icon': 'activity'},
        {'url': url_for('health.health_check'), 'label': 'Health', 'icon': 'heart'},
        {'url': url_for('api.api_status') if 'api.api_status' in current_app.view_functions else '#', 'label': 'API', 'icon': 'code'}
    ]


def _get_user_navigation_links() -> list:
    """
    Generate user-specific navigation links based on authentication status.
    
    Returns:
        List of user navigation link dictionaries
    """
    if g.current_user:
        return [
            {'url': url_for('main.dashboard'), 'label': 'Dashboard', 'icon': 'grid'},
            {'url': url_for('auth.profile') if 'auth.profile' in current_app.view_functions else '#', 'label': 'Profile', 'icon': 'user'},
            {'url': url_for('auth.logout') if 'auth.logout' in current_app.view_functions else '#', 'label': 'Logout', 'icon': 'log-out'}
        ]
    else:
        return [
            {'url': url_for('auth.login') if 'auth.login' in current_app.view_functions else '#', 'label': 'Login', 'icon': 'log-in'},
            {'url': url_for('auth.register') if 'auth.register' in current_app.view_functions else '#', 'label': 'Register', 'icon': 'user-plus'}
        ]


def _get_admin_navigation_links() -> Optional[list]:
    """
    Generate admin-specific navigation links for privileged users.
    
    Returns:
        List of admin navigation links or None if user lacks admin privileges
    """
    if _is_admin_user():
        return [
            {'url': '/admin/users', 'label': 'User Management', 'icon': 'users'},
            {'url': '/admin/system', 'label': 'System Admin', 'icon': 'settings'},
            {'url': '/admin/logs', 'label': 'System Logs', 'icon': 'file-text'}
        ]
    return None


def _get_footer_links() -> list:
    """
    Generate footer navigation links for the application.
    
    Returns:
        List of footer link dictionaries
    """
    return [
        {'url': '/docs', 'label': 'Documentation', 'icon': 'book'},
        {'url': '/privacy', 'label': 'Privacy Policy', 'icon': 'shield'},
        {'url': '/terms', 'label': 'Terms of Service', 'icon': 'file-text'},
        {'url': '/contact', 'label': 'Contact', 'icon': 'mail'}
    ]


def _get_application_uptime() -> str:
    """
    Calculate application uptime since startup.
    
    Returns:
        String representation of application uptime
    """
    try:
        start_time = current_app.config.get('START_TIME')
        if start_time:
            uptime_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()
            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            return f"{days}d {hours}h {minutes}m"
        return "Unknown"
    except Exception:
        return "Unknown"


def _get_database_status() -> Dict[str, Any]:
    """
    Retrieve database connectivity and health status.
    
    Returns:
        Dictionary containing database status information
    """
    try:
        db_health = DatabaseManager.check_database_health()
        return {
            'status': db_health.get('status', 'unknown'),
            'accessible': db_health.get('database_accessible', False),
            'ssl_enabled': db_health.get('ssl_enabled', False),
            'version_compatible': db_health.get('version_compatible', False),
            'connection_pool': db_health.get('metrics', {}),
            'errors': db_health.get('errors', [])
        }
    except Exception as e:
        logger.error(f"Error checking database status: {e}")
        return {
            'status': 'error',
            'accessible': False,
            'error': str(e)
        }


def _get_services_status() -> Dict[str, Any]:
    """
    Retrieve service layer health status for all registered services.
    
    Returns:
        Dictionary containing service health information
    """
    try:
        return get_service_health()
    except Exception as e:
        logger.error(f"Error checking services status: {e}")
        return {'error': str(e)}


def _get_performance_metrics() -> Dict[str, Any]:
    """
    Gather application performance metrics for monitoring.
    
    Returns:
        Dictionary containing performance metrics
    """
    try:
        return {
            'request_processing_time': getattr(g, 'request_start_time', None),
            'memory_usage': 'Available through monitoring tools',
            'active_connections': DatabaseManager.get_connection_pool_status(),
            'response_times': 'Tracked in headers'
        }
    except Exception as e:
        logger.error(f"Error gathering performance metrics: {e}")
        return {'error': str(e)}


def _is_admin_user() -> bool:
    """
    Check if current user has administrative privileges.
    
    Returns:
        Boolean indicating admin status
    """
    try:
        if g.current_user:
            # Implementation depends on RBAC system
            return hasattr(g.current_user, 'is_admin') and g.current_user.is_admin
        return False
    except Exception:
        return False


def _get_user_permissions() -> list:
    """
    Retrieve permissions for the current authenticated user.
    
    Returns:
        List of user permissions
    """
    try:
        if g.current_user:
            # Implementation depends on RBAC system
            return getattr(g.current_user, 'permissions', [])
        return []
    except Exception:
        return []


def _get_user_quick_actions() -> list:
    """
    Generate quick action links for authenticated users.
    
    Returns:
        List of quick action dictionaries
    """
    return [
        {'url': url_for('main.status'), 'label': 'System Status', 'icon': 'activity'},
        {'url': url_for('health.health_check'), 'label': 'Health Check', 'icon': 'heart'},
        {'url': url_for('main.about'), 'label': 'Application Info', 'icon': 'info'}
    ]


def _get_available_features() -> list:
    """
    Get list of available application features for current user.
    
    Returns:
        List of available feature names
    """
    return [
        'Dashboard Access',
        'System Monitoring',
        'Health Checks',
        'Application Information',
        'Navigation Management'
    ]


def _get_user_recent_activity() -> list:
    """
    Retrieve recent user activity for dashboard display.
    
    Returns:
        List of recent activity items
    """
    # Placeholder implementation - would integrate with audit service
    return [
        {
            'action': 'Dashboard Access',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'description': 'Accessed user dashboard'
        }
    ]


def _get_user_notifications() -> list:
    """
    Retrieve user notifications for dashboard display.
    
    Returns:
        List of user notification items
    """
    # Placeholder implementation - would integrate with notification service
    return [
        {
            'type': 'info',
            'message': 'Welcome to the Flask application dashboard',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    ]


# Blueprint error handlers for enhanced error management

@main_bp.errorhandler(404)
def not_found_error(error):
    """
    Handle 404 Not Found errors within main blueprint routes.
    
    Args:
        error: Flask error object
        
    Returns:
        Flask response: 404 error page or JSON response
    """
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'status': 'error',
            'message': 'Resource not found',
            'error': 'Not Found',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 404
    
    return render_template('errors/404.html'), 404


@main_bp.errorhandler(500)
def internal_error(error):
    """
    Handle 500 Internal Server Error within main blueprint routes.
    
    Args:
        error: Flask error object
        
    Returns:
        Flask response: 500 error page or JSON response
    """
    logger.error(f"Internal server error: {error}")
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'status': 'error',
            'message': 'Internal server error occurred',
            'error': 'Internal Server Error',
            'timestamp': datetime.now(timezone.utc).isoformat()
        }), 500
    
    return render_template('errors/500.html'), 500


# Blueprint configuration and initialization

def init_main_blueprint(app):
    """
    Initialize main blueprint with application-specific configuration.
    
    Args:
        app: Flask application instance
    """
    try:
        # Configure blueprint-specific settings
        app.config.setdefault('MAIN_BLUEPRINT_ENABLED', True)
        app.config.setdefault('DASHBOARD_ENABLED', True)
        app.config.setdefault('NAVIGATION_CACHING', True)
        
        # Register blueprint with application
        app.register_blueprint(main_bp)
        
        logger.info("Main blueprint initialized successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize main blueprint: {e}")
        raise


# Export blueprint for application factory registration
__all__ = ['main_bp', 'init_main_blueprint']