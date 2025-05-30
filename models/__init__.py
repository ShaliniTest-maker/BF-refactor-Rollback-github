"""
Flask-SQLAlchemy Database Initialization Module

This module provides centralized database configuration, model imports, and Flask application
integration for the Flask 3.1.1 migration. Implements Flask-SQLAlchemy 3.1.1 with PostgreSQL
14.12+ backend support, enterprise-grade connection pooling, and comprehensive model access.

Key Features:
- Flask-SQLAlchemy 3.1.1 database instance with PostgreSQL connection configuration
- Enterprise-grade connection pooling (pool_size=20, max_overflow=30, pool_timeout=30)
- Centralized model imports for Flask application factory pattern integration
- Database initialization functions with comprehensive error handling
- Environment variable configuration management for production deployment
- Connection validation and health check utilities
- Performance monitoring and metrics integration support

Database Configuration:
- Primary Database: PostgreSQL 14.12+ with SSL/TLS encryption enforcement
- Connection Pooling: pgbouncer-compatible settings for enterprise scalability
- Connection Pool: 20 base connections + 30 overflow (50 total concurrent connections)
- Pool Timeout: 30 seconds for connection acquisition with automatic retry
- Pool Recycle: 3600 seconds (1 hour) for connection lifecycle management
- Pre-ping Validation: Automatic connection validation before query execution

Model Architecture:
- BaseModel: Common functionality and audit field support through AuditMixin
- User Models: User, UserSession with Flask-Login integration and RBAC support
- RBAC Models: Role, Permission, UserRole, RolePermission with comprehensive authorization
- Business Models: BusinessEntity, EntityRelationship for business logic operations
- Audit Models: AuditLog, SecurityEvent for compliance and security monitoring

Dependencies:
- Flask-SQLAlchemy 3.1.1: ORM functionality and declarative models
- PostgreSQL 14.12+: Primary database with JSONB, SSL, and advanced indexing
- psycopg2-binary: PostgreSQL Python adapter with connection pooling
- python-dotenv: Environment variable management for configuration
- SQLAlchemy-Utils: EncryptedType and additional utilities for enhanced functionality
"""

import os
import logging
from typing import Dict, Any, Optional, Union
from contextlib import contextmanager

# Core Flask and SQLAlchemy imports
from flask import Flask, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, create_engine, inspect
from sqlalchemy.exc import SQLAlchemyError, OperationalError, IntegrityError
from sqlalchemy.pool import QueuePool
from sqlalchemy.engine import Engine

# Environment variable management
from dotenv import load_dotenv

# Load environment variables for database configuration
load_dotenv()

# Configure logging for database operations
logger = logging.getLogger(__name__)

# Global SQLAlchemy instance - initialized by Flask application factory
db = SQLAlchemy()


class DatabaseError(Exception):
    """Custom exception for database initialization and configuration errors."""
    pass


class DatabaseManager:
    """
    Database management utility class for configuration, monitoring, and maintenance.
    
    Provides high-level database operations including:
    - Connection validation and health checks
    - Performance monitoring and metrics collection
    - Database initialization and migration support
    - Configuration validation and environment management
    - Transaction management utilities for service layer integration
    """
    
    @staticmethod
    def get_database_config() -> Dict[str, Any]:
        """
        Retrieve comprehensive database configuration from environment variables.
        
        Returns:
            Dict containing database configuration parameters
            
        Raises:
            DatabaseError: If required configuration is missing or invalid
        """
        try:
            # Primary database URI configuration
            database_uri = os.environ.get(
                'SQLALCHEMY_DATABASE_URI',
                os.environ.get('DATABASE_URL', '')
            )
            
            if not database_uri:
                raise DatabaseError(
                    "Database URI not configured. Set SQLALCHEMY_DATABASE_URI or DATABASE_URL environment variable."
                )
            
            # Validate PostgreSQL URI format
            if not database_uri.startswith(('postgresql://', 'postgresql+psycopg2://')):
                raise DatabaseError(
                    "Database URI must be PostgreSQL format: postgresql://user:password@host:port/database"
                )
            
            # Connection pool configuration with production defaults
            pool_config = {
                'pool_size': int(os.environ.get('SQLALCHEMY_POOL_SIZE', 20)),
                'max_overflow': int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', 30)),
                'pool_timeout': int(os.environ.get('SQLALCHEMY_POOL_TIMEOUT', 30)),
                'pool_recycle': int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 3600)),
                'pool_pre_ping': os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() == 'true'
            }
            
            # Validate pool configuration ranges
            if pool_config['pool_size'] < 1 or pool_config['pool_size'] > 100:
                raise DatabaseError("SQLALCHEMY_POOL_SIZE must be between 1 and 100")
            
            if pool_config['max_overflow'] < 0 or pool_config['max_overflow'] > 200:
                raise DatabaseError("SQLALCHEMY_MAX_OVERFLOW must be between 0 and 200")
            
            if pool_config['pool_timeout'] < 1 or pool_config['pool_timeout'] > 300:
                raise DatabaseError("SQLALCHEMY_POOL_TIMEOUT must be between 1 and 300 seconds")
            
            # Performance and optimization configuration
            engine_config = {
                'echo': os.environ.get('SQLALCHEMY_ENGINE_ECHO', 'false').lower() == 'true',
                'echo_pool': os.environ.get('SQLALCHEMY_ENGINE_ECHO_POOL', 'false').lower() == 'true',
                'track_modifications': os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS', 'false').lower() == 'true',
                'isolation_level': os.environ.get('SQLALCHEMY_ENGINE_ISOLATION_LEVEL', 'READ_COMMITTED')
            }
            
            # SSL and security configuration
            ssl_config = {
                'sslmode': os.environ.get('DATABASE_SSLMODE', 'require'),
                'sslcert': os.environ.get('DATABASE_SSLCERT'),
                'sslkey': os.environ.get('DATABASE_SSLKEY'),
                'sslrootcert': os.environ.get('DATABASE_SSLROOTCERT')
            }
            
            return {
                'database_uri': database_uri,
                'pool_config': pool_config,
                'engine_config': engine_config,
                'ssl_config': ssl_config
            }
            
        except (ValueError, TypeError) as e:
            raise DatabaseError(f"Invalid database configuration: {str(e)}")
    
    @staticmethod
    def create_engine_options(config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create SQLAlchemy engine options from configuration dictionary.
        
        Args:
            config: Database configuration dictionary
            
        Returns:
            Dict containing SQLAlchemy engine options
        """
        pool_config = config['pool_config']
        engine_config = config['engine_config']
        
        engine_options = {
            'poolclass': QueuePool,
            'pool_size': pool_config['pool_size'],
            'max_overflow': pool_config['max_overflow'],
            'pool_timeout': pool_config['pool_timeout'],
            'pool_recycle': pool_config['pool_recycle'],
            'pool_pre_ping': pool_config['pool_pre_ping'],
            'echo': engine_config['echo'],
            'echo_pool': engine_config['echo_pool'],
            'isolation_level': engine_config['isolation_level']
        }
        
        # Add SSL connect_args if configured
        connect_args = {}
        ssl_config = config['ssl_config']
        
        if ssl_config['sslmode']:
            connect_args['sslmode'] = ssl_config['sslmode']
        
        if ssl_config['sslcert']:
            connect_args['sslcert'] = ssl_config['sslcert']
        
        if ssl_config['sslkey']:
            connect_args['sslkey'] = ssl_config['sslkey']
        
        if ssl_config['sslrootcert']:
            connect_args['sslrootcert'] = ssl_config['sslrootcert']
        
        if connect_args:
            engine_options['connect_args'] = connect_args
        
        return engine_options
    
    @staticmethod
    def validate_database_connection(app: Flask) -> bool:
        """
        Validate database connection and configuration.
        
        Args:
            app: Flask application instance
            
        Returns:
            True if connection is valid, False otherwise
            
        Raises:
            DatabaseError: If connection validation fails
        """
        try:
            with app.app_context():
                # Test basic connection
                result = db.session.execute(text('SELECT 1')).scalar()
                if result != 1:
                    raise DatabaseError("Database connection test failed")
                
                # Validate PostgreSQL version
                version_result = db.session.execute(text('SELECT version()')).scalar()
                if 'PostgreSQL' not in version_result:
                    raise DatabaseError("Database is not PostgreSQL")
                
                # Extract version number for validation
                import re
                version_match = re.search(r'PostgreSQL (\d+)\.(\d+)', version_result)
                if version_match:
                    major_version = int(version_match.group(1))
                    if major_version < 14:
                        app.logger.warning(f"PostgreSQL version {major_version} is below recommended 14.12+")
                
                # Test connection pool
                pool = db.engine.pool
                pool_status = {
                    'size': pool.size(),
                    'checked_in': pool.checkedin(),
                    'checked_out': pool.checkedout(),
                    'overflow': pool.overflow(),
                    'invalid': pool.invalid()
                }
                
                app.logger.info(f"Database connection validated successfully. Pool status: {pool_status}")
                return True
                
        except OperationalError as e:
            raise DatabaseError(f"Database connection failed: {str(e)}")
        except Exception as e:
            raise DatabaseError(f"Database validation error: {str(e)}")
    
    @staticmethod
    def get_connection_pool_status() -> Dict[str, int]:
        """
        Get current connection pool status for monitoring.
        
        Returns:
            Dict containing pool metrics
        """
        try:
            pool = db.engine.pool
            return {
                'pool_size': pool.size(),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'invalid': pool.invalid(),
                'total_connections': pool.checkedout() + pool.checkedin() + pool.overflow()
            }
        except Exception as e:
            logger.error(f"Error getting pool status: {str(e)}")
            return {}
    
    @staticmethod
    @contextmanager
    def transaction():
        """
        Context manager for explicit transaction boundary control.
        
        Yields:
            Database session for transaction operations
            
        Raises:
            DatabaseError: If transaction fails
        """
        try:
            db.session.begin()
            yield db.session
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Transaction rolled back: {str(e)}")
            raise DatabaseError(f"Transaction failed: {str(e)}")
    
    @staticmethod
    def check_database_health() -> Dict[str, Any]:
        """
        Comprehensive database health check for monitoring.
        
        Returns:
            Dict containing health check results
        """
        health_status = {
            'status': 'unknown',
            'database_accessible': False,
            'pool_healthy': False,
            'version_compatible': False,
            'ssl_enabled': False,
            'metrics': {},
            'errors': []
        }
        
        try:
            # Test basic connectivity
            result = db.session.execute(text('SELECT 1')).scalar()
            health_status['database_accessible'] = (result == 1)
            
            # Check PostgreSQL version
            version_result = db.session.execute(text('SELECT version()')).scalar()
            health_status['version_compatible'] = 'PostgreSQL' in version_result
            
            # Check SSL status
            ssl_result = db.session.execute(text('SELECT ssl_is_used()')).scalar()
            health_status['ssl_enabled'] = ssl_result is True
            
            # Check connection pool status
            pool_status = DatabaseManager.get_connection_pool_status()
            health_status['pool_healthy'] = (
                pool_status.get('invalid', 0) == 0 and 
                pool_status.get('total_connections', 0) > 0
            )
            health_status['metrics'] = pool_status
            
            # Determine overall status
            if all([
                health_status['database_accessible'],
                health_status['pool_healthy'],
                health_status['version_compatible']
            ]):
                health_status['status'] = 'healthy'
            else:
                health_status['status'] = 'degraded'
                
        except Exception as e:
            health_status['status'] = 'unhealthy'
            health_status['errors'].append(str(e))
            logger.error(f"Database health check failed: {str(e)}")
        
        return health_status


def init_database(app: Flask) -> None:
    """
    Initialize Flask-SQLAlchemy database with comprehensive configuration.
    
    This function configures the Flask application with PostgreSQL database
    support, connection pooling, and all necessary SQLAlchemy settings for
    production deployment.
    
    Args:
        app: Flask application instance
        
    Raises:
        DatabaseError: If database initialization fails
    """
    try:
        # Get database configuration from environment
        config = DatabaseManager.get_database_config()
        
        # Configure Flask-SQLAlchemy settings
        app.config['SQLALCHEMY_DATABASE_URI'] = config['database_uri']
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config['engine_config']['track_modifications']
        app.config['SQLALCHEMY_RECORD_QUERIES'] = True  # Enable query recording for monitoring
        
        # Configure engine options for PostgreSQL optimization
        engine_options = DatabaseManager.create_engine_options(config)
        app.config['SQLALCHEMY_ENGINE_OPTIONS'] = engine_options
        
        # Initialize Flask-SQLAlchemy with the application
        db.init_app(app)
        
        # Log successful configuration
        pool_config = config['pool_config']
        app.logger.info(
            f"Database initialized: PostgreSQL with pool_size={pool_config['pool_size']}, "
            f"max_overflow={pool_config['max_overflow']}, pool_timeout={pool_config['pool_timeout']}"
        )
        
        # Validate database connection
        DatabaseManager.validate_database_connection(app)
        
        # Initialize base model system
        from .base import init_base_models
        init_base_models(app)
        
        app.logger.info("Flask-SQLAlchemy database initialization completed successfully")
        
    except Exception as e:
        error_msg = f"Database initialization failed: {str(e)}"
        app.logger.error(error_msg)
        raise DatabaseError(error_msg)


def create_all_tables(app: Flask) -> None:
    """
    Create all database tables defined in models.
    
    Args:
        app: Flask application instance
        
    Raises:
        DatabaseError: If table creation fails
    """
    try:
        with app.app_context():
            # Import all models to ensure they are registered
            from . import user, rbac, business, audit
            
            # Create all tables
            db.create_all()
            
            app.logger.info("All database tables created successfully")
            
    except Exception as e:
        error_msg = f"Table creation failed: {str(e)}"
        app.logger.error(error_msg)
        raise DatabaseError(error_msg)


def drop_all_tables(app: Flask) -> None:
    """
    Drop all database tables. Use with caution!
    
    Args:
        app: Flask application instance
        
    Raises:
        DatabaseError: If table dropping fails
    """
    try:
        with app.app_context():
            db.drop_all()
            app.logger.warning("All database tables dropped")
            
    except Exception as e:
        error_msg = f"Table dropping failed: {str(e)}"
        app.logger.error(error_msg)
        raise DatabaseError(error_msg)


# Import all model classes for centralized access
try:
    # Base model components
    from .base import (
        BaseModel, 
        AuditMixin, 
        EncryptedMixin,
        DatabaseError as BaseModelError,
        EncryptionError,
        ValidationError,
        get_current_user_id,
        get_encryption_key
    )
    
    # User authentication and session models
    from .user import (
        User,
        UserSession,
        load_user
    )
    
    # RBAC (Role-Based Access Control) models
    from .rbac import (
        Role,
        Permission,
        UserRole,
        RolePermission,
        RBACManager,
        require_permission,
        require_role
    )
    
    # Business entity and relationship models
    from .business import (
        BusinessEntity,
        EntityRelationship
    )
    
    # Audit and security models
    from .audit import (
        AuditLog,
        SecurityEvent,
        AuditOperationType,
        SecurityEventSeverity,
        SecurityEventType,
        AuditManager
    )
    
    logger.info("All model classes imported successfully")
    
except ImportError as e:
    logger.error(f"Model import failed: {str(e)}")
    raise DatabaseError(f"Failed to import model classes: {str(e)}")


# Export all models and utilities for application-wide access
__all__ = [
    # Database configuration and management
    'db',
    'init_database',
    'create_all_tables',
    'drop_all_tables',
    'DatabaseManager',
    'DatabaseError',
    
    # Base model components
    'BaseModel',
    'AuditMixin',
    'EncryptedMixin',
    'EncryptionError',
    'ValidationError',
    'get_current_user_id',
    'get_encryption_key',
    
    # User models
    'User',
    'UserSession',
    'load_user',
    
    # RBAC models
    'Role',
    'Permission',
    'UserRole',
    'RolePermission',
    'RBACManager',
    'require_permission',
    'require_role',
    
    # Business models
    'BusinessEntity',
    'EntityRelationship',
    
    # Audit models
    'AuditLog',
    'SecurityEvent',
    'AuditOperationType',
    'SecurityEventSeverity',
    'SecurityEventType',
    'AuditManager'
]


def get_model_info() -> Dict[str, Any]:
    """
    Get comprehensive information about all registered models.
    
    Returns:
        Dict containing model metadata and statistics
    """
    model_info = {
        'total_models': len(__all__) - 6,  # Subtract non-model exports
        'base_models': ['BaseModel', 'AuditMixin', 'EncryptedMixin'],
        'user_models': ['User', 'UserSession'],
        'rbac_models': ['Role', 'Permission', 'UserRole', 'RolePermission'],
        'business_models': ['BusinessEntity', 'EntityRelationship'],
        'audit_models': ['AuditLog', 'SecurityEvent'],
        'utility_classes': ['DatabaseManager', 'RBACManager', 'AuditManager'],
        'decorators': ['require_permission', 'require_role'],
        'exceptions': ['DatabaseError', 'EncryptionError', 'ValidationError'],
        'enums': ['AuditOperationType', 'SecurityEventSeverity', 'SecurityEventType']
    }
    
    return model_info


def validate_model_integrity() -> Dict[str, Any]:
    """
    Validate model integrity and relationships.
    
    Returns:
        Dict containing validation results
    """
    validation_results = {
        'status': 'unknown',
        'models_validated': 0,
        'relationships_validated': 0,
        'errors': [],
        'warnings': []
    }
    
    try:
        # Validate that all models are properly imported
        core_models = [User, Role, Permission, BusinessEntity, AuditLog]
        validation_results['models_validated'] = len(core_models)
        
        # Check for required relationships
        relationships_to_check = [
            (User, 'user_roles'),
            (Role, 'user_roles'),
            (User, 'user_sessions'),
            (BusinessEntity, 'source_relationships'),
            (BusinessEntity, 'target_relationships')
        ]
        
        for model, relationship_name in relationships_to_check:
            if hasattr(model, relationship_name):
                validation_results['relationships_validated'] += 1
            else:
                validation_results['errors'].append(
                    f"Missing relationship {relationship_name} on {model.__name__}"
                )
        
        # Determine overall status
        if not validation_results['errors']:
            validation_results['status'] = 'valid'
        else:
            validation_results['status'] = 'invalid'
            
    except Exception as e:
        validation_results['status'] = 'error'
        validation_results['errors'].append(str(e))
    
    return validation_results


# Initialize logging for the models module
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger.info(f"Models module initialized with {len(__all__)} exports")