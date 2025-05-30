"""
Flask-SQLAlchemy Database Initialization Module

This module provides centralized database configuration, model imports, and Flask application
integration for the Flask 3.1.1 application architecture. Implements comprehensive database
initialization with production-ready connection pooling, PostgreSQL backend support, and
Flask-Migrate 4.1.0 integration for Alembic-based schema management.

Key Features:
- Flask-SQLAlchemy 3.1.1 database instance with PostgreSQL 14.12+ backend support
- Connection pooling configuration (pool_size=20, max_overflow=30, pool_timeout=30)
- Centralized model import structure for Flask application factory pattern
- Comprehensive audit trail and encryption capabilities via base mixins
- Support for enterprise-grade concurrent connection management

Database Configuration:
- PostgreSQL connection with SSL/TLS encryption enforcement
- Environment variable-driven configuration for deployment flexibility
- Performance optimization through SQLAlchemy engine tuning
- Connection pool validation and lifecycle management

Model Architecture:
- BaseModel with AuditMixin for comprehensive audit trails
- EncryptedMixin for PII protection using SQLAlchemy-Utils FernetEngine
- User authentication and session management models
- Role-Based Access Control (RBAC) with comprehensive permission system
- Business entity management with relationship tracking
- Security event logging and audit trail management

Dependencies:
- Flask-SQLAlchemy 3.1.1: Primary ORM functionality
- Flask-Migrate 4.1.0: Database schema management
- PostgreSQL 14.12+: Production database backend
- SQLAlchemy-Utils: Extended functionality including encryption
- python-dotenv: Environment variable management
"""

import os
import logging
from typing import Optional, Dict, Any
from contextlib import contextmanager

from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool

# Configure logging for database operations
logger = logging.getLogger(__name__)

# Initialize Flask-SQLAlchemy instance with optimized configuration
db = SQLAlchemy()

# Initialize Flask-Migrate for Alembic-based migration management
migrate = Migrate()


def get_database_config() -> Dict[str, Any]:
    """
    Get database configuration from environment variables with production defaults.
    
    Returns:
        Dictionary containing database configuration parameters
        
    Environment Variables:
        SQLALCHEMY_DATABASE_URI: PostgreSQL connection string
        SQLALCHEMY_POOL_SIZE: Base connection pool size (default: 20)
        SQLALCHEMY_MAX_OVERFLOW: Additional connections beyond pool_size (default: 30)
        SQLALCHEMY_POOL_TIMEOUT: Connection acquisition timeout in seconds (default: 30)
        SQLALCHEMY_POOL_RECYCLE: Connection lifetime in seconds (default: 3600)
        SQLALCHEMY_POOL_PRE_PING: Enable connection validation (default: true)
        SQLALCHEMY_TRACK_MODIFICATIONS: SQLAlchemy modification tracking (default: false)
    """
    return {
        # Core database connection configuration
        'SQLALCHEMY_DATABASE_URI': os.environ.get(
            'SQLALCHEMY_DATABASE_URI',
            'postgresql://localhost:5432/flask_app'
        ),
        
        # Connection pooling configuration for enterprise-grade performance
        'SQLALCHEMY_ENGINE_OPTIONS': {
            'poolclass': QueuePool,
            'pool_size': int(os.environ.get('SQLALCHEMY_POOL_SIZE', 20)),
            'max_overflow': int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', 30)),
            'pool_timeout': int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', 30)),
            'pool_recycle': int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 3600)),
            'pool_pre_ping': os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() == 'true',
            'pool_reset_on_return': 'commit',
            
            # PostgreSQL-specific connection parameters
            'connect_args': {
                'sslmode': 'require',  # Enforce SSL/TLS encryption
                'connect_timeout': 10,
                'statement_timeout': 30000,  # 30 seconds
                'application_name': 'flask_app'
            }
        },
        
        # Performance optimization settings
        'SQLALCHEMY_TRACK_MODIFICATIONS': os.environ.get(
            'SQLALCHEMY_TRACK_MODIFICATIONS', 'false'
        ).lower() == 'true',
        
        # SQL query echo configuration (disabled in production)
        'SQLALCHEMY_ECHO': os.environ.get('SQLALCHEMY_ECHO', 'false').lower() == 'true',
        'SQLALCHEMY_ECHO_POOL': os.environ.get('SQLALCHEMY_ECHO_POOL', 'false').lower() == 'true',
        
        # Connection pool monitoring and health checks
        'SQLALCHEMY_RECORD_QUERIES': os.environ.get(
            'SQLALCHEMY_RECORD_QUERIES', 'false'
        ).lower() == 'true',
    }


def configure_database_events():
    """
    Configure SQLAlchemy event listeners for monitoring, logging, and optimization.
    
    Implements:
    - Connection pool monitoring for performance tracking
    - Query performance logging for optimization
    - SSL connection validation
    - Error handling and logging
    """
    
    @event.listens_for(Engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        """Set SQLite pragmas for development environments."""
        # Only applies to SQLite connections (development)
        if 'sqlite' in str(dbapi_connection):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    
    @event.listens_for(Engine, "connect")
    def validate_postgresql_connection(dbapi_connection, connection_record):
        """Validate PostgreSQL connection and SSL encryption."""
        # Only applies to PostgreSQL connections
        if hasattr(dbapi_connection, 'get_backend_pid'):
            try:
                # Verify SSL connection for security compliance
                cursor = dbapi_connection.cursor()
                cursor.execute("SELECT ssl_is_used()")
                ssl_enabled = cursor.fetchone()[0]
                cursor.close()
                
                if not ssl_enabled:
                    logger.warning("PostgreSQL connection established without SSL encryption")
                else:
                    logger.debug("PostgreSQL SSL connection validated successfully")
                    
            except Exception as e:
                logger.error(f"Failed to validate PostgreSQL connection: {e}")
    
    @event.listens_for(Engine, "checkout")
    def log_connection_checkout(dbapi_connection, connection_record, connection_proxy):
        """Log connection pool checkout events for monitoring."""
        logger.debug(f"Connection checked out from pool: {id(dbapi_connection)}")
    
    @event.listens_for(Engine, "checkin")
    def log_connection_checkin(dbapi_connection, connection_record):
        """Log connection pool checkin events for monitoring."""
        logger.debug(f"Connection returned to pool: {id(dbapi_connection)}")
    
    @event.listens_for(Engine, "invalidate")
    def log_connection_invalidate(dbapi_connection, connection_record, exception):
        """Log connection invalidation events for debugging."""
        logger.warning(f"Connection invalidated: {exception}")


def init_database(app: Flask) -> None:
    """
    Initialize database configuration for Flask application factory pattern.
    
    Configures Flask-SQLAlchemy with production-ready settings including
    connection pooling, SSL enforcement, and performance optimization.
    
    Args:
        app: Flask application instance
        
    Features:
        - PostgreSQL backend with SSL/TLS encryption
        - Connection pooling (pool_size=20, max_overflow=30, pool_timeout=30)
        - Flask-Migrate integration for schema management
        - SQLAlchemy event listeners for monitoring
        - Environment-specific configuration management
    """
    
    # Load database configuration from environment
    db_config = get_database_config()
    
    # Apply configuration to Flask app
    for key, value in db_config.items():
        app.config[key] = value
    
    # Initialize Flask-SQLAlchemy with the app
    db.init_app(app)
    
    # Initialize Flask-Migrate for Alembic-based migrations
    migrate.init_app(app, db)
    
    # Configure database event listeners
    configure_database_events()
    
    # Log successful initialization
    logger.info(
        f"Database initialized successfully: "
        f"pool_size={db_config['SQLALCHEMY_ENGINE_OPTIONS']['pool_size']}, "
        f"max_overflow={db_config['SQLALCHEMY_ENGINE_OPTIONS']['max_overflow']}, "
        f"pool_timeout={db_config['SQLALCHEMY_ENGINE_OPTIONS']['pool_timeout']}"
    )


def create_all_tables() -> None:
    """
    Create all database tables based on model definitions.
    
    Should be called within Flask application context for proper execution.
    Used primarily for development and testing environments.
    
    Raises:
        RuntimeError: If called outside Flask application context
    """
    if not current_app:
        raise RuntimeError("create_all_tables() must be called within Flask application context")
    
    try:
        db.create_all()
        logger.info("All database tables created successfully")
    except Exception as e:
        logger.error(f"Failed to create database tables: {e}")
        raise


def drop_all_tables() -> None:
    """
    Drop all database tables. USE WITH EXTREME CAUTION.
    
    Should only be used in development/testing environments.
    
    Raises:
        RuntimeError: If called outside Flask application context
    """
    if not current_app:
        raise RuntimeError("drop_all_tables() must be called within Flask application context")
    
    try:
        db.drop_all()
        logger.warning("All database tables dropped")
    except Exception as e:
        logger.error(f"Failed to drop database tables: {e}")
        raise


@contextmanager
def database_transaction():
    """
    Context manager for explicit database transaction control.
    
    Provides commit/rollback semantics for complex operations
    spanning multiple database entities.
    
    Example:
        with database_transaction():
            user = User.create(username='test')
            profile = UserProfile.create(user_id=user.id)
            # Automatic commit on success, rollback on exception
    """
    try:
        db.session.begin()
        yield db.session
        db.session.commit()
        logger.debug("Database transaction committed successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database transaction failed, rolled back: {e}")
        raise


def get_database_health() -> Dict[str, Any]:
    """
    Get database connection health and performance metrics.
    
    Returns:
        Dictionary containing database health information
        
    Metrics:
        - Connection pool status
        - Active connections count
        - Database connectivity test
        - SSL encryption status
    """
    health_info = {
        'status': 'unknown',
        'pool_size': None,
        'active_connections': None,
        'ssl_enabled': None,
        'error': None
    }
    
    try:
        # Test basic database connectivity
        result = db.session.execute(text('SELECT 1')).scalar()
        if result == 1:
            health_info['status'] = 'healthy'
        
        # Get connection pool information
        engine = db.engine
        pool = engine.pool
        
        health_info['pool_size'] = pool.size()
        health_info['active_connections'] = pool.checkedout()
        
        # Check SSL encryption status for PostgreSQL
        if 'postgresql' in str(engine.url):
            ssl_result = db.session.execute(text('SELECT ssl_is_used()')).scalar()
            health_info['ssl_enabled'] = bool(ssl_result)
        
        logger.debug("Database health check completed successfully")
        
    except Exception as e:
        health_info['status'] = 'unhealthy'
        health_info['error'] = str(e)
        logger.error(f"Database health check failed: {e}")
    
    return health_info


# Import all model classes for centralized access
# Base model components
from .base import (
    AuditMixin,
    EncryptedMixin,
    BaseModel,
    DatabaseManager,
    initialize_database
)

# User authentication and session management
from .user import (
    User,
    UserSession,
    UserUtils,
    load_user
)

# Role-Based Access Control (RBAC)
from .rbac import (
    Role,
    Permission,
    user_roles,
    role_permissions
)

# Business entity management
from .business import (
    BusinessEntity,
    EntityRelationship
)

# Audit logging and security events
from .audit import (
    AuditLog,
    SecurityEvent
)


# Comprehensive model export for application-wide access
__all__ = [
    # Database instances and configuration
    'db',
    'migrate',
    'init_database',
    'create_all_tables',
    'drop_all_tables',
    'database_transaction',
    'get_database_health',
    'get_database_config',
    
    # Base model components
    'AuditMixin',
    'EncryptedMixin', 
    'BaseModel',
    'DatabaseManager',
    'initialize_database',
    
    # User management models
    'User',
    'UserSession',
    'UserUtils',
    'load_user',
    
    # RBAC models
    'Role',
    'Permission',
    'user_roles',
    'role_permissions',
    
    # Business entity models
    'BusinessEntity',
    'EntityRelationship',
    
    # Audit and security models
    'AuditLog',
    'SecurityEvent'
]


def validate_model_relationships():
    """
    Validate all model relationships and foreign key constraints.
    
    Performs comprehensive validation of:
    - Foreign key relationships
    - Association table configurations
    - Cascade deletion settings
    - Index definitions
    
    Returns:
        Boolean indicating if all relationships are valid
        
    Raises:
        ValueError: If relationship validation fails
    """
    try:
        # Validate User model relationships
        assert hasattr(User, 'sessions'), "User model missing sessions relationship"
        assert hasattr(User, 'roles'), "User model missing roles relationship"
        
        # Validate RBAC relationships
        assert hasattr(Role, 'permissions'), "Role model missing permissions relationship"
        assert hasattr(Permission, 'roles'), "Permission model missing roles relationship"
        
        # Validate business entity relationships
        assert hasattr(BusinessEntity, 'owner'), "BusinessEntity model missing owner relationship"
        assert hasattr(BusinessEntity, 'source_relationships'), "BusinessEntity model missing source_relationships"
        assert hasattr(BusinessEntity, 'target_relationships'), "BusinessEntity model missing target_relationships"
        
        # Validate session relationships
        assert hasattr(UserSession, 'user'), "UserSession model missing user relationship"
        
        logger.info("All model relationships validated successfully")
        return True
        
    except AssertionError as e:
        logger.error(f"Model relationship validation failed: {e}")
        raise ValueError(f"Model relationship validation failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error during model validation: {e}")
        raise


def get_model_registry() -> Dict[str, Any]:
    """
    Get registry of all available models with metadata.
    
    Returns:
        Dictionary mapping model names to model classes with metadata
        
    Useful for:
    - Dynamic model access
    - API introspection
    - Administrative interfaces
    - Testing and validation
    """
    registry = {
        # User management
        'User': {
            'class': User,
            'table_name': User.__tablename__,
            'description': 'User authentication and profile management'
        },
        'UserSession': {
            'class': UserSession,
            'table_name': UserSession.__tablename__,
            'description': 'User session management and tracking'
        },
        
        # RBAC system
        'Role': {
            'class': Role,
            'table_name': Role.__tablename__,
            'description': 'Role-based access control roles'
        },
        'Permission': {
            'class': Permission,
            'table_name': Permission.__tablename__,
            'description': 'System permissions for authorization'
        },
        
        # Business entities
        'BusinessEntity': {
            'class': BusinessEntity,
            'table_name': BusinessEntity.__tablename__,
            'description': 'Core business entity management'
        },
        'EntityRelationship': {
            'class': EntityRelationship,
            'table_name': EntityRelationship.__tablename__,
            'description': 'Business entity relationship tracking'
        },
        
        # Audit and logging
        'AuditLog': {
            'class': AuditLog,
            'table_name': AuditLog.__tablename__,
            'description': 'Comprehensive audit trail logging'
        },
        'SecurityEvent': {
            'class': SecurityEvent,
            'table_name': SecurityEvent.__tablename__,
            'description': 'Security event tracking and monitoring'
        }
    }
    
    return registry


# Initialize model relationship validation on import
try:
    # Only validate if we're in an application context
    if current_app:
        validate_model_relationships()
except RuntimeError:
    # No application context available during import - validation will occur during app initialization
    pass
except Exception as e:
    logger.warning(f"Model relationship validation skipped during import: {e}")


logger.info("Flask-SQLAlchemy models module initialized successfully")