"""
Utilities Package for Flask Application

This module provides centralized access to all utility functions and classes
used throughout the Flask application. It establishes the utils package namespace
and organizes cross-cutting concerns for the Flask 3.1.1 application factory pattern.

The utilities are organized into functional areas:
- Configuration management for Flask application factory pattern
- Database operations and Flask-SQLAlchemy integration
- DateTime operations with timezone awareness
- Error handling and exception management
- Structured logging with AWS CloudWatch integration
- Application monitoring and health checks
- HTTP response formatting and API utilities
- Data serialization and transformation
- Input validation and sanitization

Usage:
    # Import specific utilities
    from src.utils import get_config, validate_email, format_response
    
    # Import utility modules for more comprehensive access
    from src.utils import config, validation, response
    
    # Import utility classes for advanced functionality
    from src.utils import DatabaseManager, ErrorHandler, LoggingManager

Architecture Integration:
    - Flask application factory pattern integration via configuration utilities
    - Service Layer pattern support through business logic utilities
    - Blueprint modular architecture support via cross-cutting concerns
    - Cross-cutting concerns organization for enhanced maintainability

Version: Flask 3.1.1 compatible
Python: 3.13.3 compatible
"""

# Configuration Management Utilities
# Provides Flask application factory pattern configuration support
from .config import (
    get_config,
    load_environment_config,
    validate_config,
    ConfigurationManager,
    DevelopmentConfig,
    StagingConfig,
    ProductionConfig
)

# Database Utilities
# Flask-SQLAlchemy integration and PostgreSQL connection management
from .database import (
    get_db_session,
    create_database_connection,
    close_database_connection,
    execute_transaction,
    DatabaseManager,
    ConnectionPoolManager,
    MigrationHelper
)

# DateTime Utilities
# Timezone-aware datetime operations for global deployment
from .datetime import (
    utc_now,
    format_datetime,
    parse_datetime,
    convert_timezone,
    calculate_duration,
    DateTimeHelper,
    TimezoneManager
)

# Error Handling Utilities
# Flask error handlers and standardized exception management
from .error_handling import (
    handle_api_error,
    create_error_response,
    log_error,
    ErrorHandler,
    ValidationError,
    BusinessLogicError,
    DatabaseError,
    AuthenticationError
)

# Logging Utilities
# Structured JSON logging with AWS CloudWatch integration
from .logging import (
    get_logger,
    log_audit_event,
    log_security_event,
    create_correlation_id,
    LoggingManager,
    AuditLogger,
    SecurityLogger
)

# Monitoring Utilities
# Prometheus metrics integration and health check endpoints
from .monitoring import (
    record_metric,
    check_health,
    create_metrics_endpoint,
    MonitoringManager,
    HealthChecker,
    MetricsCollector,
    PerformanceMonitor
)

# Response Utilities
# HTTP response formatting and API response helpers
from .response import (
    create_response,
    create_error_response as format_error_response,
    create_paginated_response,
    add_cors_headers,
    ResponseFormatter,
    PaginationHelper,
    CORSManager
)

# Serialization Utilities
# JSON serialization with datetime and decimal support
from .serialization import (
    serialize_data,
    deserialize_data,
    serialize_datetime,
    serialize_decimal,
    DataSerializer,
    JSONEncoder,
    SecureSerializer
)

# Validation Utilities
# Input validation, sanitization, and security pattern detection
from .validation import (
    validate_email,
    validate_password,
    sanitize_input,
    validate_json_schema,
    ValidationHelper,
    InputSanitizer,
    SchemaValidator,
    SecurityValidator
)

# Utility Collections for Enhanced Organization
# Grouped utility access for specific functional areas

class ConfigurationUtils:
    """Configuration utilities collection for Flask application factory pattern."""
    
    def __init__(self):
        self.manager = ConfigurationManager()
        self.get_config = get_config
        self.load_environment_config = load_environment_config
        self.validate_config = validate_config

class DatabaseUtils:
    """Database utilities collection for Flask-SQLAlchemy integration."""
    
    def __init__(self):
        self.manager = DatabaseManager()
        self.connection_pool = ConnectionPoolManager()
        self.migration_helper = MigrationHelper()
        self.get_session = get_db_session
        self.execute_transaction = execute_transaction

class MonitoringUtils:
    """Monitoring utilities collection for observability and health checks."""
    
    def __init__(self):
        self.manager = MonitoringManager()
        self.health_checker = HealthChecker()
        self.metrics_collector = MetricsCollector()
        self.performance_monitor = PerformanceMonitor()
        self.record_metric = record_metric
        self.check_health = check_health

class SecurityUtils:
    """Security utilities collection for authentication and validation."""
    
    def __init__(self):
        self.validator = SecurityValidator()
        self.sanitizer = InputSanitizer()
        self.validate_email = validate_email
        self.validate_password = validate_password
        self.sanitize_input = sanitize_input

class ResponseUtils:
    """Response utilities collection for API response formatting."""
    
    def __init__(self):
        self.formatter = ResponseFormatter()
        self.pagination_helper = PaginationHelper()
        self.cors_manager = CORSManager()
        self.create_response = create_response
        self.create_paginated_response = create_paginated_response

# Initialize utility collections for convenient access
config_utils = ConfigurationUtils()
database_utils = DatabaseUtils()
monitoring_utils = MonitoringUtils()
security_utils = SecurityUtils()
response_utils = ResponseUtils()

# Export collections for external use
__all__ = [
    # Configuration Management
    'get_config',
    'load_environment_config',
    'validate_config',
    'ConfigurationManager',
    'DevelopmentConfig',
    'StagingConfig',
    'ProductionConfig',
    
    # Database Utilities
    'get_db_session',
    'create_database_connection',
    'close_database_connection',
    'execute_transaction',
    'DatabaseManager',
    'ConnectionPoolManager',
    'MigrationHelper',
    
    # DateTime Utilities
    'utc_now',
    'format_datetime',
    'parse_datetime',
    'convert_timezone',
    'calculate_duration',
    'DateTimeHelper',
    'TimezoneManager',
    
    # Error Handling
    'handle_api_error',
    'create_error_response',
    'log_error',
    'ErrorHandler',
    'ValidationError',
    'BusinessLogicError',
    'DatabaseError',
    'AuthenticationError',
    
    # Logging Utilities
    'get_logger',
    'log_audit_event',
    'log_security_event',
    'create_correlation_id',
    'LoggingManager',
    'AuditLogger',
    'SecurityLogger',
    
    # Monitoring Utilities
    'record_metric',
    'check_health',
    'create_metrics_endpoint',
    'MonitoringManager',
    'HealthChecker',
    'MetricsCollector',
    'PerformanceMonitor',
    
    # Response Utilities
    'create_response',
    'format_error_response',
    'create_paginated_response',
    'add_cors_headers',
    'ResponseFormatter',
    'PaginationHelper',
    'CORSManager',
    
    # Serialization Utilities
    'serialize_data',
    'deserialize_data',
    'serialize_datetime',
    'serialize_decimal',
    'DataSerializer',
    'JSONEncoder',
    'SecureSerializer',
    
    # Validation Utilities
    'validate_email',
    'validate_password',
    'sanitize_input',
    'validate_json_schema',
    'ValidationHelper',
    'InputSanitizer',
    'SchemaValidator',
    'SecurityValidator',
    
    # Utility Collections
    'config_utils',
    'database_utils',
    'monitoring_utils',
    'security_utils',
    'response_utils',
    
    # Utility Collection Classes
    'ConfigurationUtils',
    'DatabaseUtils',
    'MonitoringUtils',
    'SecurityUtils',
    'ResponseUtils'
]

# Version information for package compatibility
__version__ = '1.0.0'
__flask_version__ = '3.1.1'
__python_version__ = '3.13.3'

# Package metadata for Flask application factory pattern integration
__package_info__ = {
    'name': 'utils',
    'description': 'Centralized utilities for Flask application migration from Node.js',
    'architecture_pattern': 'Flask Application Factory with Service Layer',
    'blueprint_integration': True,
    'cross_cutting_concerns': True,
    'service_layer_support': True,
    'migration_context': 'Node.js to Python 3.13.3/Flask 3.1.1'
}

def get_package_info():
    """
    Returns package information for Flask application factory integration.
    
    Returns:
        dict: Package metadata including version and architecture information
    """
    return __package_info__.copy()

def initialize_utils(app=None):
    """
    Initialize utilities for Flask application factory pattern integration.
    
    This function can be called during Flask application factory initialization
    to configure utility modules with application-specific settings.
    
    Args:
        app: Flask application instance (optional)
    
    Returns:
        dict: Initialized utility managers for application integration
    """
    initialized_utils = {
        'config': ConfigurationManager(),
        'database': DatabaseManager(),
        'logging': LoggingManager(),
        'monitoring': MonitoringManager(),
        'error_handler': ErrorHandler()
    }
    
    # Configure utilities with Flask app if provided
    if app is not None:
        for util_name, util_manager in initialized_utils.items():
            if hasattr(util_manager, 'init_app'):
                util_manager.init_app(app)
    
    return initialized_utils

# Cross-cutting concern utilities for Service Layer pattern integration
def setup_cross_cutting_concerns(app):
    """
    Setup cross-cutting concerns for Flask application architecture.
    
    Configures logging, monitoring, error handling, and security utilities
    for consistent behavior across all Flask blueprints and services.
    
    Args:
        app: Flask application instance
    
    Returns:
        dict: Configured cross-cutting concern utilities
    """
    cross_cutting_utils = {
        'logging': get_logger(__name__),
        'monitoring': MonitoringManager(),
        'error_handling': ErrorHandler(),
        'security': SecurityValidator(),
        'response_formatting': ResponseFormatter()
    }
    
    # Initialize each cross-cutting concern with the Flask app
    for concern_name, concern_util in cross_cutting_utils.items():
        if hasattr(concern_util, 'init_app'):
            concern_util.init_app(app)
    
    # Log successful initialization
    cross_cutting_utils['logging'].info(
        'Cross-cutting concerns initialized for Flask application',
        extra={
            'concerns': list(cross_cutting_utils.keys()),
            'flask_version': __flask_version__,
            'python_version': __python_version__
        }
    )
    
    return cross_cutting_utils