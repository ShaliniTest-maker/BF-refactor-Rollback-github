"""
Main Application Blueprint for Flask 3.1.1 Application

This blueprint provides core Flask route definitions for non-API endpoints including 
index pages, navigation routes, and general application functionality. Implements 
Flask blueprint patterns replacing Express.js main route handlers while preserving
complete functional parity and maintaining compatibility with existing client 
applications.

Key Features:
- Flask 3.1.1 blueprint pattern with route decorator implementation
- Request/response handling using Flask request context and jsonify()
- Service layer integration for business logic coordination
- Template rendering for web page delivery
- Error handling and proper HTTP status code management
- Session management integration with authentication system
- Modular route organization supporting application factory pattern

Architecture:
This blueprint follows the Flask blueprint management system specified in Section 5.2.2,
implementing modular route organization that replaces Express.js main route handlers
while maintaining identical external behavior and response formats for seamless
client compatibility during the Node.js to Flask migration.

Route Categories:
- Main application routes: home, index, about, navigation
- User dashboard and profile pages
- Application information and documentation routes
- Static content delivery coordination
- Error page handling and user experience management
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, Union, Tuple
from datetime import datetime

from flask import (
    Blueprint, 
    render_template, 
    request, 
    jsonify, 
    redirect, 
    url_for, 
    session, 
    current_app, 
    flash,
    abort,
    g
)
from werkzeug.exceptions import NotFound, BadRequest, InternalServerError

# Import service layer for business logic coordination
from services import get_service, with_service, ServiceException
from models import User, db

# Configure logging for main blueprint operations
logger = logging.getLogger(__name__)

# Create main blueprint with Flask 3.1.1 patterns
main_bp = Blueprint(
    'main',
    __name__,
    template_folder='../templates',
    static_folder='../static',
    url_prefix='/'
)


@main_bp.before_request
def load_user_context():
    """
    Load user context for all main blueprint requests.
    
    This function runs before each request to establish user context,
    session validation, and authentication state for proper request
    processing throughout main application routes.
    
    Features:
    - User authentication state validation
    - Session management integration
    - Request context preparation
    - Service availability verification
    """
    try:
        # Initialize request context variables
        g.user = None
        g.authenticated = False
        g.user_roles = []
        
        # Check for authenticated user session
        if 'user_id' in session:
            auth_service = get_service('auth')
            user_id = session.get('user_id')
            
            # Validate and load user from session
            user = auth_service.get_authenticated_user(user_id)
            if user:
                g.user = user
                g.authenticated = True
                g.user_roles = [role.name for role in user.roles] if hasattr(user, 'roles') else []
                
                logger.debug(f"User context loaded: {user.username}")
            else:
                # Clear invalid session
                session.clear()
                logger.warning(f"Invalid session cleared for user_id: {user_id}")
        
        # Log request for monitoring and debugging
        logger.debug(
            f"Request processed: {request.method} {request.path} - "
            f"User: {g.user.username if g.user else 'Anonymous'}"
        )
        
    except ServiceException as e:
        logger.error(f"Service error in user context loading: {e}")
        # Continue with anonymous user context
        g.user = None
        g.authenticated = False
        g.user_roles = []
    except Exception as e:
        logger.error(f"Unexpected error in user context loading: {e}")
        # Continue with anonymous user context
        g.user = None
        g.authenticated = False
        g.user_roles = []


@main_bp.route('/', methods=['GET'])
def index():
    """
    Main application index route - primary entry point.
    
    Serves the main application landing page with dynamic content based on
    user authentication status, user preferences, and application state.
    Replaces Express.js main route handler with Flask template rendering.
    
    Returns:
        Rendered template or JSON response based on request headers
        
    Features:
    - Dynamic content based on authentication status
    - User personalization and dashboard preview
    - Application statistics and information
    - Responsive design with mobile optimization
    - SEO-optimized meta tags and content structure
    """
    try:
        # Gather application statistics and user context
        context = {
            'page_title': 'Welcome to Flask Application',
            'authenticated': g.authenticated,
            'user': g.user,
            'current_time': datetime.utcnow(),
            'app_version': current_app.config.get('APP_VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'production')
        }
        
        # Add authenticated user context
        if g.authenticated and g.user:
            user_service = get_service('user')
            
            # Get user dashboard preview data
            dashboard_data = user_service.get_user_dashboard_summary(g.user.id)
            context.update({
                'user_dashboard': dashboard_data,
                'user_roles': g.user_roles,
                'last_login': g.user.last_login_at if hasattr(g.user, 'last_login_at') else None
            })
            
            logger.debug(f"Index page loaded for authenticated user: {g.user.username}")
        else:
            # Anonymous user content
            context.update({
                'show_registration': True,
                'show_login': True,
                'public_features': [
                    'Secure user authentication',
                    'Modern Flask architecture',
                    'RESTful API endpoints',
                    'Responsive web interface'
                ]
            })
            
            logger.debug("Index page loaded for anonymous user")
        
        # Handle AJAX/API requests with JSON response
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'success',
                'data': context,
                'authenticated': g.authenticated,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Render main index template
        return render_template('main/index.html', **context)
        
    except ServiceException as e:
        logger.error(f"Service error in index route: {e}")
        flash('An error occurred while loading the page. Please try again.', 'error')
        
        # Return error response based on request type
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Service temporarily unavailable',
                'error_code': 'SERVICE_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500
        
    except Exception as e:
        logger.error(f"Unexpected error in index route: {e}")
        
        # Return generic error response
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'An unexpected error occurred',
                'error_code': 'UNEXPECTED_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500


@main_bp.route('/about', methods=['GET'])
def about():
    """
    About page route providing application information and documentation.
    
    Serves comprehensive information about the Flask application including
    features, architecture, API documentation, and technical specifications.
    Supports both HTML template rendering and JSON API responses.
    
    Returns:
        Rendered about template or JSON application information
        
    Features:
    - Application architecture overview
    - Feature list and capabilities
    - API documentation links
    - Technical stack information
    - Contact and support information
    """
    try:
        # Compile application information
        app_info = {
            'application_name': 'Flask Migration Application',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'environment': current_app.config.get('FLASK_ENV', 'production'),
            'flask_version': '3.1.1',
            'python_version': '3.13.3',
            'architecture': 'Flask Blueprint-based Monolithic Application',
            
            # Technical stack information
            'tech_stack': {
                'web_framework': 'Flask 3.1.1',
                'database': 'PostgreSQL 14.12+ with Flask-SQLAlchemy 3.1.1',
                'authentication': 'Flask-Login 0.6.3 with ItsDangerous 2.2+',
                'migrations': 'Flask-Migrate 4.1.0 with Alembic',
                'session_management': 'Flask sessions with cryptographic protection',
                'testing': 'Pytest with Flask testing utilities'
            },
            
            # Application features
            'features': [
                'RESTful API endpoints with complete Node.js parity',
                'User authentication and session management',
                'Role-based access control (RBAC)',
                'Database migration and version control',
                'Comprehensive audit logging',
                'Health monitoring and metrics',
                'Enterprise-grade security',
                'Modular blueprint architecture'
            ],
            
            # API documentation
            'api_documentation': {
                'base_url': request.host_url + 'api/v1',
                'endpoints': [
                    '/api/v1/users - User management operations',
                    '/api/v1/auth - Authentication endpoints',
                    '/api/v1/health - System health monitoring',
                    '/api/v1/docs - API documentation'
                ],
                'authentication': 'Session-based with CSRF protection',
                'response_format': 'JSON with consistent error handling'
            }
        }
        
        # Add deployment information for authenticated users
        if g.authenticated:
            app_info['deployment'] = {
                'container_ready': True,
                'kubernetes_compatible': True,
                'docker_image': 'python:3.13.3-slim',
                'wsgi_server': 'Gunicorn 20.x / uWSGI 2.x',
                'monitoring': 'Python logging with structured output'
            }
        
        # Handle JSON API requests
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'success',
                'data': app_info,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Render about template
        return render_template('main/about.html', app_info=app_info)
        
    except Exception as e:
        logger.error(f"Error in about route: {e}")
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Failed to load application information',
                'error_code': 'INFO_LOAD_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500


@main_bp.route('/dashboard')
@with_service('user')
def dashboard(user_service):
    """
    User dashboard route with authentication requirement.
    
    Provides authenticated users with personalized dashboard including
    account information, recent activity, system notifications, and
    quick access to primary application features.
    
    Args:
        user_service: Injected user service for business logic
        
    Returns:
        Rendered dashboard template or redirect to login
        
    Features:
    - User profile summary and settings
    - Recent activity and audit trail
    - System notifications and alerts
    - Quick action buttons and navigation
    - Performance metrics and usage statistics
    """
    # Require authentication for dashboard access
    if not g.authenticated:
        flash('Please log in to access your dashboard.', 'info')
        return redirect(url_for('auth.login'))
    
    try:
        # Get comprehensive user dashboard data
        dashboard_data = user_service.get_user_dashboard(g.user.id)
        
        # Prepare dashboard context
        context = {
            'page_title': f'Dashboard - {g.user.username}',
            'user': g.user,
            'user_roles': g.user_roles,
            'dashboard_data': dashboard_data,
            'last_login': dashboard_data.get('last_login'),
            'account_status': dashboard_data.get('account_status', 'active'),
            
            # Recent activity and notifications
            'recent_activities': dashboard_data.get('recent_activities', []),
            'notifications': dashboard_data.get('notifications', []),
            'unread_count': dashboard_data.get('unread_notifications', 0),
            
            # Usage statistics
            'usage_stats': dashboard_data.get('usage_statistics', {}),
            'session_count': dashboard_data.get('session_count', 0),
            
            # Quick actions
            'quick_actions': [
                {'name': 'Profile Settings', 'url': url_for('main.profile')},
                {'name': 'Account Security', 'url': url_for('auth.security')},
                {'name': 'API Documentation', 'url': '/api/v1/docs'},
                {'name': 'System Health', 'url': url_for('health.system_status')}
            ]
        }
        
        # Handle JSON API requests for dashboard data
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'success',
                'data': context,
                'user_id': g.user.id,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Render dashboard template
        logger.info(f"Dashboard accessed by user: {g.user.username}")
        return render_template('main/dashboard.html', **context)
        
    except ServiceException as e:
        logger.error(f"Service error in dashboard route for user {g.user.id}: {e}")
        flash('Unable to load dashboard data. Please try again.', 'error')
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Dashboard data unavailable',
                'error_code': 'DASHBOARD_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500
        
    except Exception as e:
        logger.error(f"Unexpected error in dashboard route for user {g.user.id}: {e}")
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Dashboard temporarily unavailable',
                'error_code': 'UNEXPECTED_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500


@main_bp.route('/profile')
@with_service('user')
def profile(user_service):
    """
    User profile page route with authentication requirement.
    
    Displays user profile information including personal details,
    account settings, security configuration, and preference management.
    Supports both viewing and editing capabilities.
    
    Args:
        user_service: Injected user service for profile operations
        
    Returns:
        Rendered profile template or redirect to login
        
    Features:
    - Personal information display and editing
    - Account security settings
    - User preference management
    - Activity history and audit trail
    - Profile picture and avatar management
    """
    # Require authentication for profile access
    if not g.authenticated:
        flash('Please log in to access your profile.', 'info')
        return redirect(url_for('auth.login'))
    
    try:
        # Get detailed user profile data
        profile_data = user_service.get_user_profile(g.user.id)
        
        # Prepare profile context
        context = {
            'page_title': f'Profile - {g.user.username}',
            'user': g.user,
            'profile_data': profile_data,
            'user_roles': g.user_roles,
            'editable': True,  # Profile owner can edit
            
            # Profile sections
            'personal_info': profile_data.get('personal_info', {}),
            'account_settings': profile_data.get('account_settings', {}),
            'security_settings': profile_data.get('security_settings', {}),
            'preferences': profile_data.get('preferences', {}),
            
            # Activity and audit information
            'last_password_change': profile_data.get('last_password_change'),
            'account_created': profile_data.get('created_at'),
            'login_history': profile_data.get('recent_logins', []),
            
            # Security status
            'two_factor_enabled': profile_data.get('two_factor_enabled', False),
            'password_strength': profile_data.get('password_strength', 'unknown'),
            'security_score': profile_data.get('security_score', 0)
        }
        
        # Handle JSON API requests for profile data
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'success',
                'data': context,
                'user_id': g.user.id,
                'editable': True,
                'timestamp': datetime.utcnow().isoformat()
            })
        
        # Render profile template
        logger.info(f"Profile accessed by user: {g.user.username}")
        return render_template('main/profile.html', **context)
        
    except ServiceException as e:
        logger.error(f"Service error in profile route for user {g.user.id}: {e}")
        flash('Unable to load profile data. Please try again.', 'error')
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Profile data unavailable',
                'error_code': 'PROFILE_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500
        
    except Exception as e:
        logger.error(f"Unexpected error in profile route for user {g.user.id}: {e}")
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({
                'status': 'error',
                'message': 'Profile temporarily unavailable',
                'error_code': 'UNEXPECTED_ERROR'
            }), 500
        
        return render_template('errors/500.html'), 500


@main_bp.route('/navigation')
def navigation():
    """
    Navigation menu API endpoint for dynamic menu generation.
    
    Provides dynamic navigation menu structure based on user authentication
    status, roles, and permissions. Supports both full navigation and
    contextual menu generation for AJAX requests.
    
    Returns:
        JSON response with navigation structure or rendered navigation template
        
    Features:
    - Role-based navigation filtering
    - Dynamic menu item generation
    - Permission-aware link visibility
    - Mobile-responsive navigation structure
    - Breadcrumb navigation support
    """
    try:
        # Base navigation structure
        navigation_items = [
            {
                'name': 'Home',
                'url': url_for('main.index'),
                'icon': 'home',
                'public': True,
                'order': 1
            },
            {
                'name': 'About',
                'url': url_for('main.about'),
                'icon': 'info',
                'public': True,
                'order': 2
            }
        ]
        
        # Add authenticated user navigation
        if g.authenticated:
            authenticated_items = [
                {
                    'name': 'Dashboard',
                    'url': url_for('main.dashboard'),
                    'icon': 'dashboard',
                    'public': False,
                    'order': 3
                },
                {
                    'name': 'Profile',
                    'url': url_for('main.profile'),
                    'icon': 'user',
                    'public': False,
                    'order': 4
                },
                {
                    'name': 'API Documentation',
                    'url': '/api/v1/docs',
                    'icon': 'api',
                    'public': False,
                    'order': 5
                }
            ]
            
            # Add admin navigation for admin users
            if 'admin' in g.user_roles:
                admin_items = [
                    {
                        'name': 'System Health',
                        'url': url_for('health.system_status'),
                        'icon': 'health',
                        'public': False,
                        'roles': ['admin'],
                        'order': 6
                    },
                    {
                        'name': 'User Management',
                        'url': '/admin/users',
                        'icon': 'users',
                        'public': False,
                        'roles': ['admin'],
                        'order': 7
                    }
                ]
                authenticated_items.extend(admin_items)
            
            navigation_items.extend(authenticated_items)
            
            # Add logout link
            navigation_items.append({
                'name': 'Logout',
                'url': url_for('auth.logout'),
                'icon': 'logout',
                'public': False,
                'order': 99
            })
        else:
            # Anonymous user navigation
            anonymous_items = [
                {
                    'name': 'Login',
                    'url': url_for('auth.login'),
                    'icon': 'login',
                    'public': True,
                    'order': 8
                },
                {
                    'name': 'Register',
                    'url': url_for('auth.register'),
                    'icon': 'user-plus',
                    'public': True,
                    'order': 9
                }
            ]
            navigation_items.extend(anonymous_items)
        
        # Filter navigation based on user roles
        filtered_navigation = []
        for item in navigation_items:
            # Check role requirements
            if 'roles' in item:
                if not any(role in g.user_roles for role in item['roles']):
                    continue
            
            # Check public access
            if not item.get('public', False) and not g.authenticated:
                continue
            
            filtered_navigation.append(item)
        
        # Sort navigation by order
        filtered_navigation.sort(key=lambda x: x.get('order', 50))
        
        # Prepare navigation context
        navigation_data = {
            'items': filtered_navigation,
            'authenticated': g.authenticated,
            'user': g.user.username if g.user else None,
            'user_roles': g.user_roles,
            'current_path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Always return JSON for navigation endpoint
        return jsonify({
            'status': 'success',
            'navigation': navigation_data
        })
        
    except Exception as e:
        logger.error(f"Error generating navigation: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Navigation unavailable',
            'error_code': 'NAVIGATION_ERROR'
        }), 500


@main_bp.route('/status')
def application_status():
    """
    Application status endpoint for monitoring and health checks.
    
    Provides basic application status information including uptime,
    version, and basic system health indicators. Used for monitoring
    and load balancer health checks.
    
    Returns:
        JSON response with application status information
        
    Features:
    - Application uptime and version information
    - Basic health indicators
    - Service availability status
    - System resource utilization
    - Environment information
    """
    try:
        status_info = {
            'application': 'Flask Migration Application',
            'version': current_app.config.get('APP_VERSION', '1.0.0'),
            'status': 'healthy',
            'environment': current_app.config.get('FLASK_ENV', 'production'),
            'flask_version': '3.1.1',
            'python_version': '3.13.3',
            'timestamp': datetime.utcnow().isoformat(),
            
            # Basic system information
            'uptime': 'Available',  # Could be calculated from app start time
            'database_status': 'connected',  # Basic check
            'session_storage': 'available',
            'service_layer': 'operational',
            
            # Feature availability
            'features': {
                'authentication': True,
                'user_management': True,
                'api_endpoints': True,
                'health_monitoring': True,
                'audit_logging': True
            }
        }
        
        # Perform basic database connectivity check
        try:
            from models import get_database_health
            db_health = get_database_health()
            status_info['database_status'] = db_health.get('status', 'unknown')
        except Exception as db_error:
            logger.warning(f"Database health check failed: {db_error}")
            status_info['database_status'] = 'unavailable'
            status_info['status'] = 'degraded'
        
        # Check service availability
        try:
            auth_service = get_service('auth')
            user_service = get_service('user')
            status_info['service_layer'] = 'operational'
        except Exception as service_error:
            logger.warning(f"Service layer check failed: {service_error}")
            status_info['service_layer'] = 'degraded'
            status_info['status'] = 'degraded'
        
        return jsonify(status_info)
        
    except Exception as e:
        logger.error(f"Error in application status endpoint: {e}")
        return jsonify({
            'application': 'Flask Migration Application',
            'status': 'error',
            'error': 'Status check failed',
            'timestamp': datetime.utcnow().isoformat()
        }), 500


@main_bp.errorhandler(404)
def not_found_error(error):
    """
    Handle 404 Not Found errors for main blueprint routes.
    
    Provides user-friendly error pages and JSON error responses
    for missing routes within the main application blueprint.
    
    Args:
        error: Flask error object
        
    Returns:
        Rendered error template or JSON error response
    """
    logger.warning(f"404 error on {request.method} {request.path}")
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'status': 'error',
            'error': 'Not Found',
            'message': 'The requested resource was not found',
            'error_code': 'NOT_FOUND',
            'path': request.path,
            'timestamp': datetime.utcnow().isoformat()
        }), 404
    
    return render_template('errors/404.html'), 404


@main_bp.errorhandler(500)
def internal_error(error):
    """
    Handle 500 Internal Server Error for main blueprint routes.
    
    Provides user-friendly error pages and JSON error responses
    for server errors within the main application blueprint.
    
    Args:
        error: Flask error object
        
    Returns:
        Rendered error template or JSON error response
    """
    logger.error(f"500 error on {request.method} {request.path}: {error}")
    
    # Rollback database session on errors
    db.session.rollback()
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'status': 'error',
            'error': 'Internal Server Error',
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR',
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    
    return render_template('errors/500.html'), 500


# Blueprint teardown handler for cleanup
@main_bp.teardown_request
def cleanup_request(exception=None):
    """
    Clean up resources after each request in the main blueprint.
    
    Ensures proper resource cleanup including database sessions,
    service instances, and request context variables after each
    request to prevent memory leaks and maintain application stability.
    
    Args:
        exception: Optional exception that occurred during request processing
    """
    try:
        # Clear user context variables
        if hasattr(g, 'user'):
            g.user = None
        if hasattr(g, 'authenticated'):
            g.authenticated = False
        if hasattr(g, 'user_roles'):
            g.user_roles.clear()
        
        # Log cleanup completion
        logger.debug("Main blueprint request cleanup completed")
        
    except Exception as cleanup_error:
        logger.error(f"Error during main blueprint cleanup: {cleanup_error}")


# Blueprint registration information for application factory
main_blueprint_info = {
    'blueprint': main_bp,
    'url_prefix': '/',
    'name': 'main',
    'description': 'Main application routes for non-API endpoints',
    'version': '1.0.0',
    'dependencies': ['services', 'models', 'auth'],
    'routes': [
        {'path': '/', 'methods': ['GET'], 'name': 'index'},
        {'path': '/about', 'methods': ['GET'], 'name': 'about'},
        {'path': '/dashboard', 'methods': ['GET'], 'name': 'dashboard'},
        {'path': '/profile', 'methods': ['GET'], 'name': 'profile'},
        {'path': '/navigation', 'methods': ['GET'], 'name': 'navigation'},
        {'path': '/status', 'methods': ['GET'], 'name': 'application_status'}
    ]
}


# Export blueprint for application factory registration
__all__ = ['main_bp', 'main_blueprint_info']