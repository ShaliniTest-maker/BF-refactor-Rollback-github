#!/usr/bin/env python3
"""
WSGI Entry Point for Flask Application Production Deployment

This module provides the WSGI interface between production WSGI servers (Gunicorn/uWSGI)
and the Flask application. It handles production configuration loading, environment 
variable management, and container orchestration integration for Kubernetes deployment.

Features:
- Gunicorn 20.x WSGI server compatibility with optimized worker configuration
- uWSGI 2.x alternative support with master process configuration
- Container orchestration integration for Kubernetes deployment
- Production environment configuration loading with environment variable strategy
- Health check endpoint integration for load balancer health monitoring
- Graceful shutdown handling for production WSGI server management
- Performance optimized application instance creation

Usage:
    # Gunicorn deployment (recommended)
    gunicorn --config gunicorn.conf.py wsgi:application
    
    # uWSGI deployment (alternative)
    uwsgi --module wsgi:application --callable application
    
    # Development testing
    python wsgi.py

Environment Variables:
    FLASK_ENV: Flask environment (production, development, testing)
    FLASK_CONFIG: Configuration class name (default: 'production')
    DATABASE_URL: PostgreSQL connection string for SQLAlchemy
    SECRET_KEY: Flask session security key
    
Author: Flask Migration Team
Version: 1.0.0
Created: 2024-12-19
"""

import os
import sys
import logging
import signal
from typing import Optional

# Configure Python path for production deployment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import Flask application factory and configuration
    from app import create_app
    from config import Config, ProductionConfig, DevelopmentConfig, TestingConfig
except ImportError as e:
    # Handle import errors gracefully for production deployment
    logging.error(f"Failed to import Flask application components: {e}")
    logging.error("Ensure app.py and config.py are present in the deployment directory")
    sys.exit(1)


class WSGIApplicationFactory:
    """
    Factory class for creating and managing WSGI application instances.
    
    Provides centralized application creation with proper error handling,
    configuration management, and production deployment optimizations.
    """
    
    def __init__(self):
        self.application = None
        self._is_initialized = False
        self._config_class = None
        
    def create_application(self, config_name: Optional[str] = None) -> object:
        """
        Create Flask application instance with production configuration.
        
        Args:
            config_name: Configuration environment name (production, development, testing)
            
        Returns:
            Flask application instance configured for WSGI deployment
            
        Raises:
            RuntimeError: If application creation fails
        """
        try:
            # Determine configuration class based on environment
            config_name = config_name or os.environ.get('FLASK_CONFIG', 'production')
            
            # Map configuration names to classes
            config_mapping = {
                'production': ProductionConfig,
                'development': DevelopmentConfig,
                'testing': TestingConfig,
                'default': ProductionConfig
            }
            
            self._config_class = config_mapping.get(config_name.lower(), ProductionConfig)
            
            # Log configuration selection for deployment tracking
            logging.info(f"Initializing Flask application with {self._config_class.__name__}")
            
            # Create Flask application using factory pattern
            app = create_app(self._config_class)
            
            # Validate critical production requirements
            self._validate_production_config(app)
            
            # Configure production logging
            self._configure_production_logging(app)
            
            # Register health check endpoints for load balancer integration
            self._register_health_endpoints(app)
            
            # Configure graceful shutdown handling
            self._setup_graceful_shutdown(app)
            
            self.application = app
            self._is_initialized = True
            
            logging.info("Flask application successfully initialized for WSGI deployment")
            return app
            
        except Exception as e:
            logging.error(f"Failed to create Flask application: {e}")
            logging.error("Application startup failed - check configuration and dependencies")
            raise RuntimeError(f"WSGI application creation failed: {e}")
    
    def _validate_production_config(self, app):
        """
        Validate critical production configuration requirements.
        
        Args:
            app: Flask application instance
            
        Raises:
            RuntimeError: If critical configuration is missing
        """
        required_config = ['SECRET_KEY', 'SQLALCHEMY_DATABASE_URI']
        missing_config = []
        
        for config_key in required_config:
            if not app.config.get(config_key):
                missing_config.append(config_key)
        
        if missing_config:
            raise RuntimeError(
                f"Missing critical configuration: {', '.join(missing_config)}. "
                "Ensure all required environment variables are set."
            )
        
        # Validate database URL format for PostgreSQL
        db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
        if not db_url.startswith(('postgresql://', 'postgresql+psycopg2://')):
            logging.warning(
                "Database URL does not appear to be PostgreSQL format. "
                "Ensure DATABASE_URL environment variable is correctly set."
            )
    
    def _configure_production_logging(self, app):
        """
        Configure production-grade logging for WSGI deployment.
        
        Args:
            app: Flask application instance
        """
        if not app.debug:
            # Configure structured logging for production
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s %(levelname)s [%(name)s] [%(filename)s:%(lineno)d] %(message)s',
                handlers=[
                    logging.StreamHandler(sys.stdout)
                ]
            )
            
            # Set Flask application logger level
            app.logger.setLevel(logging.INFO)
            
            # Configure SQLAlchemy logging for production
            logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)
            logging.getLogger('sqlalchemy.pool').setLevel(logging.WARNING)
    
    def _register_health_endpoints(self, app):
        """
        Register health check endpoints for load balancer integration.
        
        Args:
            app: Flask application instance
        """
        @app.route('/health')
        def health_check():
            """
            Basic health check endpoint for load balancer monitoring.
            
            Returns:
                JSON response with application health status
            """
            try:
                # Perform basic application health checks
                health_status = {
                    'status': 'healthy',
                    'application': 'flask-app',
                    'version': '1.0.0',
                    'environment': app.config.get('ENV', 'production'),
                    'database': 'connected'
                }
                
                # Test database connectivity if available
                try:
                    from flask_sqlalchemy import SQLAlchemy
                    db = app.extensions.get('sqlalchemy')
                    if db:
                        db.engine.execute('SELECT 1')
                        health_status['database'] = 'connected'
                    else:
                        health_status['database'] = 'not_configured'
                except Exception as db_error:
                    health_status['database'] = 'disconnected'
                    health_status['database_error'] = str(db_error)
                    app.logger.warning(f"Database health check failed: {db_error}")
                
                return health_status, 200
                
            except Exception as e:
                app.logger.error(f"Health check failed: {e}")
                return {
                    'status': 'unhealthy',
                    'error': str(e),
                    'application': 'flask-app'
                }, 503
        
        @app.route('/ready')
        def readiness_check():
            """
            Kubernetes readiness probe endpoint.
            
            Returns:
                JSON response indicating application readiness for traffic
            """
            try:
                # Perform readiness checks
                readiness_status = {
                    'ready': True,
                    'application': 'flask-app',
                    'checks': {
                        'config_loaded': bool(app.config.get('SECRET_KEY')),
                        'blueprints_registered': len(app.blueprints) > 0,
                        'database_configured': bool(app.config.get('SQLALCHEMY_DATABASE_URI'))
                    }
                }
                
                # Check if all readiness criteria are met
                all_ready = all(readiness_status['checks'].values())
                readiness_status['ready'] = all_ready
                
                status_code = 200 if all_ready else 503
                return readiness_status, status_code
                
            except Exception as e:
                app.logger.error(f"Readiness check failed: {e}")
                return {
                    'ready': False,
                    'error': str(e),
                    'application': 'flask-app'
                }, 503
        
        @app.route('/metrics')
        def metrics_endpoint():
            """
            Basic metrics endpoint for monitoring integration.
            
            Returns:
                JSON response with basic application metrics
            """
            try:
                metrics_data = {
                    'application': 'flask-app',
                    'version': '1.0.0',
                    'environment': app.config.get('ENV', 'production'),
                    'uptime_seconds': 0,  # To be implemented with startup time tracking
                    'registered_blueprints': list(app.blueprints.keys()),
                    'blueprint_count': len(app.blueprints),
                    'route_count': len([rule for rule in app.url_map.iter_rules()])
                }
                
                return metrics_data, 200
                
            except Exception as e:
                app.logger.error(f"Metrics endpoint failed: {e}")
                return {
                    'error': str(e),
                    'application': 'flask-app'
                }, 500
    
    def _setup_graceful_shutdown(self, app):
        """
        Configure graceful shutdown handling for production WSGI servers.
        
        Args:
            app: Flask application instance
        """
        def shutdown_handler(signum, frame):
            """Handle graceful shutdown signals."""
            app.logger.info(f"Received shutdown signal {signum}, initiating graceful shutdown")
            
            # Perform cleanup operations
            try:
                # Close database connections if available
                db = app.extensions.get('sqlalchemy')
                if db and hasattr(db, 'engine'):
                    db.engine.dispose()
                    app.logger.info("Database connections closed")
                
                app.logger.info("Graceful shutdown completed")
                
            except Exception as e:
                app.logger.error(f"Error during graceful shutdown: {e}")
            
            sys.exit(0)
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)


# Create global WSGI application factory instance
wsgi_factory = WSGIApplicationFactory()

# Create the WSGI application instance
try:
    application = wsgi_factory.create_application()
except Exception as init_error:
    logging.error(f"WSGI application initialization failed: {init_error}")
    # Create a minimal error application for debugging
    from flask import Flask
    application = Flask(__name__)
    
    @application.route('/')
    def error_page():
        return {
            'error': 'Application initialization failed',
            'message': str(init_error),
            'status': 'error'
        }, 500


def get_application():
    """
    Get the WSGI application instance.
    
    This function provides an alternative entry point for WSGI servers
    that prefer function-based application retrieval.
    
    Returns:
        Flask application instance configured for WSGI deployment
    """
    global application
    if application is None:
        application = wsgi_factory.create_application()
    return application


# Gunicorn configuration integration
def create_gunicorn_app():
    """
    Create application instance optimized for Gunicorn deployment.
    
    Recommended Gunicorn configuration:
    - Workers: 2-4 per CPU core
    - Worker class: sync for CPU-bound, gevent for I/O-bound
    - Worker timeout: 30 seconds
    - Graceful timeout: 30 seconds
    - Keep-alive: 5 seconds
    
    Returns:
        Flask application instance optimized for Gunicorn
    """
    return get_application()


# uWSGI configuration integration
def create_uwsgi_app():
    """
    Create application instance optimized for uWSGI deployment.
    
    Recommended uWSGI configuration:
    - Master process: enabled
    - Workers: 2-4 per CPU core
    - Async support: gevent for I/O-intensive operations
    - Buffer size: 32768
    - Max requests: 1000 for worker recycling
    
    Returns:
        Flask application instance optimized for uWSGI
    """
    return get_application()


if __name__ == '__main__':
    """
    Development server entry point for testing WSGI configuration.
    
    This should not be used in production - use Gunicorn or uWSGI instead.
    """
    print("WSGI Development Server")
    print("=" * 50)
    print("Starting Flask application in development mode")
    print("For production deployment, use Gunicorn or uWSGI")
    print("=" * 50)
    
    try:
        # Override configuration for development testing
        dev_app = wsgi_factory.create_application('development')
        
        # Display application information
        print(f"Configuration: {wsgi_factory._config_class.__name__}")
        print(f"Debug mode: {dev_app.debug}")
        print(f"Registered blueprints: {list(dev_app.blueprints.keys())}")
        print(f"Total routes: {len([rule for rule in dev_app.url_map.iter_rules()])}")
        print("=" * 50)
        
        # Start development server
        dev_app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=True,
            use_reloader=True
        )
        
    except Exception as e:
        print(f"Failed to start development server: {e}")
        sys.exit(1)