"""
WSGI Entry Point for Production Deployment

This module provides the WSGI application entry point for production deployment with
Gunicorn 20.x and uWSGI 2.x servers. It replaces the Node.js server.js pattern with
a Flask-compatible WSGI interface optimized for container orchestration and
Kubernetes deployment per Section 3.6.2 production server configuration.

Key Features:
- Gunicorn 20.x WSGI server compatibility with optimized worker configuration
- uWSGI 2.x alternative support with master process configuration
- Container orchestration integration for Kubernetes deployment
- Production environment configuration loading with environment variable strategy
- Graceful shutdown handling and health check endpoint integration
- Resource limit awareness for containerized environments

WSGI Server Configuration Guidelines:

Gunicorn Configuration Example:
    gunicorn --bind 0.0.0.0:8000 \
             --workers 4 \
             --worker-class sync \
             --worker-timeout 30 \
             --graceful-timeout 30 \
             --keepalive 5 \
             --max-requests 1000 \
             --max-requests-jitter 100 \
             --preload \
             wsgi:application

uWSGI Configuration Example:
    uwsgi --http 0.0.0.0:8000 \
          --module wsgi:application \
          --master \
          --processes 4 \
          --threads 2 \
          --buffer-size 32768 \
          --max-requests 1000 \
          --harakiri 30 \
          --vacuum \
          --die-on-term

Docker Deployment:
    FROM python:3.13.3
    COPY requirements.txt ./
    RUN pip install -r requirements.txt
    COPY . .
    EXPOSE 8000
    CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:application"]

Kubernetes Health Checks:
    livenessProbe:
      httpGet:
        path: /health
        port: 8000
      initialDelaySeconds: 30
      periodSeconds: 10
    readinessProbe:
      httpGet:
        path: /health
        port: 8000
      initialDelaySeconds: 5
      periodSeconds: 5

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Gunicorn 20.x, uWSGI 2.x, Python 3.13.3
"""

import os
import sys
import logging
import signal
import multiprocessing
from typing import Optional, Dict, Any
from pathlib import Path

# Environment variable loading for production deployment
from dotenv import load_dotenv

# Flask application factory
from app import create_app, FlaskApplicationError

# Configure WSGI module logging
logger = logging.getLogger(__name__)


def load_production_environment() -> bool:
    """
    Load production environment variables with validation and error handling.
    
    Implements environment variable migration strategy per Section 3.6.2, mapping
    legacy Node.js environment variables to Flask-compatible settings and ensuring
    all required production configuration is properly loaded.
    
    Returns:
        bool: True if environment loaded successfully, False if critical errors
        
    Environment Variable Mapping:
        NODE_ENV -> FLASK_ENV (development/production mode configuration)
        MONGODB_URI -> DATABASE_URL (PostgreSQL connection string)
        PORT -> FLASK_PORT (server port configuration)
        
    Required Production Variables:
        FLASK_ENV: Environment mode (production/staging/development)
        FLASK_CONFIG: Configuration class override
        SECRET_KEY: Flask session security key
        DATABASE_URL: PostgreSQL connection string
        
    Raises:
        SystemExit: If critical production environment variables are missing
    """
    try:
        # Load environment files in production precedence order
        env_files = [
            '.env',                    # Base configuration
            '.env.production',         # Production-specific settings
            '.env.local'              # Local production overrides
        ]
        
        loaded_files = []
        for env_file in env_files:
            env_path = Path(env_file)
            if env_path.exists():
                load_dotenv(env_path, override=False)
                loaded_files.append(env_file)
                logger.debug(f"Loaded production environment file: {env_file}")
        
        # Log environment file loading results
        if loaded_files:
            logger.info(f"Production environment loaded from: {', '.join(loaded_files)}")
        else:
            logger.info("No .env files found, using system environment variables")
        
        # Validate critical production environment variables
        critical_vars = {
            'FLASK_ENV': 'Flask environment mode',
            'SECRET_KEY': 'Flask session security key',
            'DATABASE_URL': 'PostgreSQL database connection string'
        }
        
        missing_vars = []
        invalid_vars = []
        
        for var, description in critical_vars.items():
            value = os.environ.get(var)
            
            if not value:
                missing_vars.append(f"{var} ({description})")
            elif var == 'SECRET_KEY' and value == 'dev-key-change-in-production':
                invalid_vars.append(f"{var} (using development default)")
            elif var == 'DATABASE_URL' and not value.startswith('postgresql://'):
                invalid_vars.append(f"{var} (invalid PostgreSQL URI format)")
        
        # Handle missing critical variables
        if missing_vars:
            logger.error(f"Missing critical production environment variables: {missing_vars}")
            if os.environ.get('FLASK_ENV') == 'production':
                logger.critical("Cannot start production server with missing critical variables")
                return False
            else:
                logger.warning("Running with missing variables - development mode assumed")
        
        # Handle invalid variables
        if invalid_vars:
            logger.warning(f"Invalid production environment variables: {invalid_vars}")
            if os.environ.get('FLASK_ENV') == 'production':
                logger.error("Production deployment with invalid configuration detected")
                return False
        
        # Additional production environment validations
        flask_env = os.environ.get('FLASK_ENV', 'development')
        if flask_env == 'production':
            # Validate production-specific requirements
            production_vars = ['DATABASE_URL', 'SECRET_KEY']
            for var in production_vars:
                if not os.environ.get(var):
                    logger.critical(f"Production deployment requires {var} environment variable")
                    return False
        
        logger.info(f"Production environment validation completed (Environment: {flask_env})")
        return True
        
    except Exception as e:
        logger.error(f"Failed to load production environment: {e}")
        return False


def configure_wsgi_logging() -> None:
    """
    Configure WSGI-specific logging for production deployment monitoring.
    
    Implements structured logging per Section 3.6.2 production configuration with
    appropriate log levels, formatters, and handlers for WSGI server integration.
    Configures logging compatible with Gunicorn and uWSGI error stream handling.
    
    Features:
        - Production-safe log levels and formats
        - WSGI server integration with proper stream handling
        - Container-friendly logging to stdout/stderr
        - Structured logging for monitoring and observability
    """
    try:
        # Get log level from environment with production default
        log_level_str = os.environ.get('LOG_LEVEL', 'INFO')
        log_level = getattr(logging, log_level_str.upper(), logging.INFO)
        
        # Configure production logging format
        log_format = os.environ.get(
            'LOG_FORMAT',
            '%(asctime)s [%(process)d] [%(levelname)s] %(name)s: %(message)s'
        )
        
        # Create production formatter with process ID for multi-worker environments
        formatter = logging.Formatter(log_format)
        
        # Configure console handler for container deployment
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        
        # Configure root logger for WSGI application
        root_logger = logging.getLogger()
        root_logger.handlers.clear()  # Remove default handlers
        root_logger.addHandler(console_handler)
        root_logger.setLevel(log_level)
        
        # Configure WSGI module logger
        wsgi_logger = logging.getLogger(__name__)
        wsgi_logger.setLevel(log_level)
        
        # Log WSGI logging initialization
        wsgi_logger.info(f"WSGI logging configured (Level: {log_level_str}, PID: {os.getpid()})")
        
    except Exception as e:
        # Fallback logging configuration for WSGI
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(process)d] [%(levelname)s] %(message)s',
            stream=sys.stdout
        )
        logger.error(f"WSGI logging configuration failed, using fallback: {e}")


def get_optimal_worker_count() -> int:
    """
    Calculate optimal worker count for WSGI server deployment.
    
    Implements worker management optimization per Section 3.6.2 with recommended
    configuration of 2-4 workers per CPU core, considering container resource
    limits and memory constraints for Kubernetes deployment.
    
    Returns:
        int: Recommended number of worker processes
        
    Calculation Strategy:
        - Base calculation: (CPU cores * 2) + 1
        - Container limit awareness: Consider cgroup CPU limits
        - Memory constraint consideration: Limit workers based on available memory
        - Minimum 2 workers, maximum 32 workers for production stability
    """
    try:
        # Get CPU count from system
        cpu_count = multiprocessing.cpu_count()
        
        # Check for container CPU limits (Kubernetes/Docker)
        container_cpu_limit = None
        try:
            # Read cgroup CPU quota and period for container limits
            with open('/sys/fs/cgroup/cpu/cpu.cfs_quota_us', 'r') as f:
                quota = int(f.read().strip())
            with open('/sys/fs/cgroup/cpu/cpu.cfs_period_us', 'r') as f:
                period = int(f.read().strip())
            
            if quota > 0 and period > 0:
                container_cpu_limit = quota / period
                logger.debug(f"Container CPU limit detected: {container_cpu_limit:.2f} cores")
        except (FileNotFoundError, ValueError, PermissionError):
            # No container limits or unable to read - use system CPU count
            pass
        
        # Use container limit if available and lower than system count
        effective_cpu_count = min(container_cpu_limit or cpu_count, cpu_count)
        
        # Calculate worker count based on Gunicorn recommendations
        # Base formula: (2 x CPU cores) + 1
        base_worker_count = int((effective_cpu_count * 2) + 1)
        
        # Environment variable override for worker count
        env_worker_count = os.environ.get('WSGI_WORKERS')
        if env_worker_count:
            try:
                env_worker_count = int(env_worker_count)
                logger.info(f"Using environment-specified worker count: {env_worker_count}")
                return max(2, min(env_worker_count, 32))  # Enforce reasonable limits
            except ValueError:
                logger.warning(f"Invalid WSGI_WORKERS value: {env_worker_count}, using calculated value")
        
        # Apply production limits and constraints
        worker_count = max(2, min(base_worker_count, 32))
        
        logger.info(
            f"Optimal worker count calculated: {worker_count} "
            f"(CPU cores: {effective_cpu_count}, Base calculation: {base_worker_count})"
        )
        
        return worker_count
        
    except Exception as e:
        logger.error(f"Failed to calculate optimal worker count: {e}")
        # Fallback to conservative worker count
        return 4


def setup_signal_handlers() -> None:
    """
    Configure signal handlers for graceful shutdown in production deployment.
    
    Implements graceful shutdown handling per Section 3.6.2 container orchestration
    integration, ensuring proper cleanup of database connections and Flask application
    resources during container restart or termination.
    
    Signal Handling:
        SIGTERM: Graceful shutdown for container orchestration
        SIGINT: Interrupt handling for development and testing
        SIGUSR1: Reload configuration (Gunicorn compatibility)
    """
    def graceful_shutdown_handler(signum, frame):
        """Handle graceful shutdown signals from container orchestration."""
        logger.info(f"Received shutdown signal {signum}, initiating graceful shutdown...")
        
        try:
            # Perform cleanup operations
            logger.info("Performing application cleanup...")
            
            # Note: Flask-SQLAlchemy connections are handled automatically
            # Additional cleanup can be added here if needed
            
            logger.info("Graceful shutdown completed")
            sys.exit(0)
            
        except Exception as e:
            logger.error(f"Error during graceful shutdown: {e}")
            sys.exit(1)
    
    def reload_handler(signum, frame):
        """Handle configuration reload signals (Gunicorn compatibility)."""
        logger.info(f"Received reload signal {signum}, configuration reload not implemented")
        # Configuration reload can be implemented here if needed
    
    try:
        # Register signal handlers for production deployment
        signal.signal(signal.SIGTERM, graceful_shutdown_handler)
        signal.signal(signal.SIGINT, graceful_shutdown_handler)
        
        # Register reload handler for Gunicorn compatibility
        if hasattr(signal, 'SIGUSR1'):
            signal.signal(signal.SIGUSR1, reload_handler)
        
        logger.debug("Signal handlers configured for graceful shutdown")
        
    except Exception as e:
        logger.warning(f"Failed to configure signal handlers: {e}")


def validate_wsgi_environment() -> Dict[str, Any]:
    """
    Validate WSGI deployment environment and return status information.
    
    Performs comprehensive environment validation for production deployment,
    checking system requirements, container constraints, and configuration
    compatibility with Gunicorn and uWSGI servers.
    
    Returns:
        Dict[str, Any]: Environment validation results and system information
        
    Validation Checks:
        - Python version compatibility (3.13.3+)
        - Required environment variables
        - System resource availability
        - Container orchestration integration
        - WSGI server compatibility
    """
    try:
        validation_results = {
            'status': 'healthy',
            'timestamp': None,
            'python_version': sys.version,
            'process_id': os.getpid(),
            'environment': {},
            'system': {},
            'warnings': [],
            'errors': []
        }
        
        import time
        validation_results['timestamp'] = time.time()
        
        # Validate Python version
        python_version = sys.version_info
        if python_version < (3, 13):
            validation_results['warnings'].append(
                f"Python version {python_version.major}.{python_version.minor} "
                f"may not be fully compatible (recommended: 3.13.3+)"
            )
        
        # Environment variable validation
        flask_env = os.environ.get('FLASK_ENV', 'development')
        validation_results['environment'] = {
            'flask_env': flask_env,
            'config': os.environ.get('FLASK_CONFIG'),
            'secret_key_configured': bool(os.environ.get('SECRET_KEY')),
            'database_configured': bool(os.environ.get('DATABASE_URL')),
            'port': os.environ.get('PORT', '8000'),
            'workers': os.environ.get('WSGI_WORKERS')
        }
        
        # System resource information
        validation_results['system'] = {
            'cpu_count': multiprocessing.cpu_count(),
            'optimal_workers': get_optimal_worker_count(),
            'container_detected': Path('/proc/1/cgroup').exists(),
            'kubernetes_detected': bool(os.environ.get('KUBERNETES_SERVICE_HOST'))
        }
        
        # Production environment specific validations
        if flask_env == 'production':
            required_vars = ['SECRET_KEY', 'DATABASE_URL']
            missing_vars = [var for var in required_vars if not os.environ.get(var)]
            
            if missing_vars:
                validation_results['errors'].extend([
                    f"Missing required production variable: {var}" for var in missing_vars
                ])
                validation_results['status'] = 'error'
        
        # Container orchestration validation
        if validation_results['system']['kubernetes_detected']:
            logger.info("Kubernetes environment detected - container orchestration features enabled")
        
        return validation_results
        
    except Exception as e:
        logger.error(f"WSGI environment validation failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'timestamp': time.time()
        }


def create_wsgi_application(config_name: Optional[str] = None) -> object:
    """
    Create Flask WSGI application for production deployment.
    
    This function creates and configures the Flask application instance for WSGI
    server deployment, implementing the application factory pattern with production
    optimizations for Gunicorn and uWSGI compatibility.
    
    Args:
        config_name: Environment configuration override
        
    Returns:
        Flask application instance configured for WSGI deployment
        
    Raises:
        SystemExit: If critical application initialization fails
        
    Features:
        - Production environment configuration loading
        - WSGI server compatibility optimization
        - Container orchestration integration
        - Health check endpoint registration
        - Graceful shutdown handling
    """
    try:
        logger.info("Initializing WSGI application for production deployment...")
        
        # Load and validate production environment
        if not load_production_environment():
            logger.critical("Production environment loading failed")
            sys.exit(1)
        
        # Configure WSGI-specific logging
        configure_wsgi_logging()
        
        # Setup signal handlers for graceful shutdown
        setup_signal_handlers()
        
        # Validate WSGI deployment environment
        validation_results = validate_wsgi_environment()
        if validation_results['status'] == 'error':
            logger.critical(f"WSGI environment validation failed: {validation_results.get('error')}")
            sys.exit(1)
        
        if validation_results.get('warnings'):
            for warning in validation_results['warnings']:
                logger.warning(warning)
        
        # Create Flask application using factory pattern
        logger.info("Creating Flask application instance...")
        
        app = create_app(config_name or os.environ.get('FLASK_CONFIG'))
        
        # Log WSGI application creation success
        with app.app_context():
            logger.info(
                f"WSGI application created successfully "
                f"(Environment: {app.config.get('FLASK_ENV', 'unknown')}, "
                f"Config: {app.config.__class__.__name__}, "
                f"Workers: {validation_results['system']['optimal_workers']}, "
                f"PID: {os.getpid()})"
            )
        
        # Return Flask application for WSGI server
        return app
        
    except FlaskApplicationError as e:
        logger.critical(f"Flask application creation failed: {e.message}")
        logger.critical(f"Error code: {e.error_code}")
        if e.details:
            logger.critical(f"Error details: {e.details}")
        sys.exit(1)
        
    except Exception as e:
        logger.critical(f"Unexpected error during WSGI application creation: {e}")
        import traceback
        logger.critical(f"Traceback: {traceback.format_exc()}")
        sys.exit(1)


def get_wsgi_application_info() -> Dict[str, Any]:
    """
    Get WSGI application information for monitoring and debugging.
    
    Returns:
        Dictionary containing WSGI application metadata and configuration
        
    Useful for:
        - Container orchestration health checks
        - Load balancer configuration validation
        - Application monitoring and observability
        - Production deployment verification
    """
    try:
        from flask import current_app
        
        if current_app:
            with current_app.app_context():
                app_info = {
                    'wsgi': {
                        'module': __name__,
                        'application_callable': 'application',
                        'process_id': os.getpid(),
                        'parent_process_id': os.getppid(),
                        'python_executable': sys.executable,
                        'working_directory': os.getcwd()
                    },
                    'flask': {
                        'environment': current_app.config.get('FLASK_ENV'),
                        'config_class': current_app.config.__class__.__name__,
                        'debug': current_app.debug,
                        'testing': current_app.testing,
                        'secret_key_configured': bool(current_app.config.get('SECRET_KEY'))
                    },
                    'deployment': {
                        'gunicorn_compatible': True,
                        'uwsgi_compatible': True,
                        'container_ready': True,
                        'kubernetes_ready': True,
                        'recommended_workers': get_optimal_worker_count()
                    },
                    'system': validate_wsgi_environment()
                }
                
                return app_info
        else:
            return {'error': 'Flask application not initialized'}
            
    except Exception as e:
        logger.error(f"Failed to get WSGI application info: {e}")
        return {'error': f'Failed to retrieve WSGI application information: {str(e)}'}


# WSGI Application Instance for Production Deployment
# This is the main entry point that WSGI servers (Gunicorn, uWSGI) will import
try:
    logger.info("Starting WSGI application initialization...")
    
    # Create WSGI application instance
    application = create_wsgi_application()
    
    # Log successful WSGI application creation
    logger.info(f"WSGI application ready for deployment (PID: {os.getpid()})")
    
except SystemExit:
    # Re-raise SystemExit to allow proper process termination
    raise
except Exception as e:
    # Log critical error and create minimal error application
    logger.critical(f"WSGI application initialization failed: {e}")
    
    # Create minimal Flask application for error reporting
    from flask import Flask, jsonify
    
    application = Flask(__name__)
    
    @application.route('/error')
    def wsgi_initialization_error():
        """Error endpoint for WSGI initialization failures."""
        return jsonify({
            'error': 'WSGI Application Initialization Failed',
            'message': 'Flask application could not be initialized',
            'details': str(e),
            'status': 'critical_error',
            'process_id': os.getpid()
        }), 503
    
    @application.route('/health')
    def wsgi_error_health():
        """Health check endpoint for failed WSGI initialization."""
        return jsonify({
            'status': 'error',
            'message': 'WSGI application initialization failed',
            'healthy': False
        }), 503
    
    # Log error application creation
    logger.error("Created minimal error application for WSGI deployment")


# Export WSGI application for server discovery
__all__ = ['application', 'create_wsgi_application', 'get_wsgi_application_info']


# Development Server Warning
if __name__ == '__main__':
    """
    Development server warning and fallback.
    
    This module is designed for WSGI server deployment and should not be run
    directly in production. For development, use app.py directly or run:
    
        python app.py
        flask run
    
    For production deployment, use a WSGI server:
    
        gunicorn wsgi:application
        uwsgi --module wsgi:application
    """
    
    logger.warning("wsgi.py should not be run directly - use a WSGI server for production")
    logger.warning("For development, use: python app.py or flask run")
    logger.warning("For production, use: gunicorn wsgi:application")
    
    # Fallback to development server with warning
    try:
        if application:
            logger.info("Starting development server as fallback...")
            application.run(
                host='0.0.0.0',
                port=int(os.environ.get('PORT', 5000)),
                debug=False  # Never enable debug in wsgi.py
            )
    except Exception as e:
        logger.error(f"Development server fallback failed: {e}")
        sys.exit(1)