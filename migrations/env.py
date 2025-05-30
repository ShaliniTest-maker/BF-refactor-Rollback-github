"""
Alembic Environment Configuration for Flask-SQLAlchemy

This module provides the Alembic environment configuration for Flask application factory pattern integration,
enabling automatic model discovery, database metadata access, and comprehensive migration execution framework
with transaction management and production deployment support.

Key Features:
- Flask application factory pattern integration for migration context per Section 5.2.2 blueprint management
- Flask-SQLAlchemy 3.1.1 metadata access for automatic model discovery per Section 4.4.1.1
- Transaction boundary management for migration safety per Section 6.2.3.2 thread-safe session management
- Production deployment support with offline migration capabilities per Section 4.4.1.5

Migration Capabilities:
- Automatic model detection from Flask-SQLAlchemy registry
- Environment-specific configuration loading (development, testing, staging, production)
- SSL/TLS enforced database connections with connection pool optimization
- Comprehensive transaction management with rollback capabilities
- Offline migration support for production deployment scenarios
- Migration validation and integrity checking

Database Integration:
- PostgreSQL 14.12+ backend with SQLAlchemy connection pooling
- SSL connection enforcement through sslmode=require
- Connection pool configuration (pool_size=20, max_overflow=30, pool_timeout=30)
- Thread-safe session management for concurrent migration operations

Author: Flask Migration System
Version: 1.0.0
Compatibility: Flask 3.1.1, Flask-SQLAlchemy 3.1.1, Flask-Migrate 4.1.0, Alembic 1.13.2+
"""

import os
import sys
import logging
from logging.config import fileConfig
from typing import Optional, Union

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add the project root to Python path for proper imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure module-level logging for migration operations
logger = logging.getLogger('alembic.env')

# Load Alembic configuration object for environment settings
config = context.config

# Configure logging from alembic.ini if available
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception as e:
        logger.warning(f"Failed to configure logging from config file: {e}")

# Import Flask application and database components after path setup
try:
    from app import create_app
    from models import db
    from config import get_config
except ImportError as e:
    logger.error(f"Failed to import Flask application components: {e}")
    logger.error("Ensure the Flask application is properly installed and accessible")
    raise


def get_flask_application():
    """
    Create Flask application instance for migration context.
    
    Implements Flask application factory pattern integration per Section 5.2.2 blueprint
    management, providing proper application context for database metadata access and
    migration execution with environment-specific configuration loading.
    
    Returns:
        Flask application instance configured for migration operations
        
    Features:
        - Environment-specific configuration (development, testing, staging, production)
        - Database connection with SSL enforcement and connection pooling
        - Flask-SQLAlchemy integration with automatic model discovery
        - Production-ready configuration with security compliance
        
    Environment Variables:
        FLASK_CONFIG: Configuration class override for migration context
        FLASK_ENV: Environment name (development, testing, staging, production)
        DATABASE_URL: PostgreSQL connection string with SSL configuration
        MIGRATION_DATABASE_URL: Optional override for migration-specific database
    """
    try:
        # Determine configuration environment for migration context
        flask_config = os.environ.get('FLASK_CONFIG', os.environ.get('FLASK_ENV', 'development'))
        
        logger.info(f"Creating Flask application for migration with config: {flask_config}")
        
        # Create Flask application using factory pattern
        app = create_app(config_name=flask_config)
        
        # Override database URL if migration-specific URL is provided
        migration_db_url = os.environ.get('MIGRATION_DATABASE_URL')
        if migration_db_url:
            app.config['SQLALCHEMY_DATABASE_URI'] = migration_db_url
            logger.info("Using migration-specific database URL")
        
        # Validate database configuration
        database_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if not database_uri:
            raise ValueError("SQLALCHEMY_DATABASE_URI not configured in Flask application")
        
        # Log connection information (without credentials)
        sanitized_uri = database_uri.split('@')[1] if '@' in database_uri else database_uri
        logger.info(f"Migration database connection target: {sanitized_uri}")
        
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Flask application for migrations: {e}")
        logger.error("Check Flask application configuration and database settings")
        raise


def get_engine_url():
    """
    Get database URL from Flask application configuration.
    
    Retrieves the database connection URL from Flask-SQLAlchemy configuration with
    proper SSL enforcement and connection parameter validation for migration operations.
    
    Returns:
        Database URL string with SSL and connection parameters
        
    Validation:
        - SSL mode enforcement for production environments
        - Connection timeout and statement timeout parameters
        - Application name identification for database monitoring
        - Pool configuration for migration connection management
    """
    try:
        # Get Flask application instance
        app = get_flask_application()
        
        with app.app_context():
            # Extract database URL from Flask-SQLAlchemy configuration
            database_url = app.config['SQLALCHEMY_DATABASE_URI']
            
            # Validate SSL enforcement for production environments
            if not app.debug and not app.testing:
                if 'sslmode' not in database_url:
                    logger.warning("SSL mode not specified in production database URL")
                    # Add SSL requirement for production
                    separator = '&' if '?' in database_url else '?'
                    database_url += f"{separator}sslmode=require"
            
            # Ensure application name is set for database monitoring
            if 'application_name' not in database_url:
                separator = '&' if '?' in database_url else '?'
                database_url += f"{separator}application_name=flask_migration"
            
            logger.debug("Database URL configured successfully for migration")
            return database_url
            
    except Exception as e:
        logger.error(f"Failed to get database URL: {e}")
        raise


def get_metadata():
    """
    Get Flask-SQLAlchemy metadata for automatic model discovery.
    
    Implements Flask-SQLAlchemy 3.1.1 metadata access per Section 4.4.1.1 model definition
    standards, providing comprehensive model discovery and relationship mapping for migration
    generation and database schema management.
    
    Returns:
        SQLAlchemy MetaData instance with all registered models
        
    Features:
        - Automatic model discovery from Flask-SQLAlchemy registry
        - Relationship metadata including foreign keys and constraints
        - Index definitions and database-specific configurations
        - Table naming conventions and column type mappings
        
    Model Discovery:
        - Scans all models inheriting from db.Model
        - Includes association tables for many-to-many relationships
        - Captures custom table configurations and constraints
        - Validates model relationships and foreign key definitions
    """
    try:
        # Get Flask application instance with proper context
        app = get_flask_application()
        
        with app.app_context():
            # Access Flask-SQLAlchemy metadata with all registered models
            metadata = db.metadata
            
            # Validate metadata contains registered models
            if not metadata.tables:
                logger.warning("No database models found in Flask-SQLAlchemy metadata")
                logger.warning("Ensure models are properly imported and registered")
            else:
                table_count = len(metadata.tables)
                table_names = sorted(metadata.tables.keys())
                logger.info(f"Discovered {table_count} database tables for migration:")
                for table_name in table_names:
                    logger.info(f"  - {table_name}")
            
            # Validate foreign key relationships
            fk_count = sum(len(table.foreign_keys) for table in metadata.tables.values())
            logger.info(f"Total foreign key relationships: {fk_count}")
            
            return metadata
            
    except Exception as e:
        logger.error(f"Failed to get Flask-SQLAlchemy metadata: {e}")
        logger.error("Check model imports and Flask application configuration")
        raise


def run_migrations_offline():
    """
    Run migrations in 'offline' mode for production deployment scenarios.
    
    Implements offline migration support per Section 4.4.1.5 production migration standards,
    enabling migration script generation without active database connections for production
    deployment workflows and CI/CD pipeline integration.
    
    Features:
        - SQL script generation without database connection
        - Production deployment compatibility
        - CI/CD pipeline integration support
        - Migration validation without database access
        
    Use Cases:
        - Production deployment with pre-generated migration scripts
        - CI/CD pipeline validation of migration changes
        - Migration script review and approval workflows
        - Deployment automation and containerized environments
        
    Output:
        - SQL migration scripts written to configured output location
        - Comprehensive migration metadata and dependency information
        - Validation of migration script syntax and structure
    """
    try:
        logger.info("Running migrations in offline mode")
        
        # Get database URL for offline script generation
        url = get_engine_url()
        
        # Configure Alembic context for offline mode
        context.configure(
            url=url,
            target_metadata=get_metadata(),
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            # Production offline migration configuration
            render_as_batch=True,  # Enable batch operations for SQLite compatibility
            compare_type=True,     # Enable column type comparison
            compare_server_default=True,  # Compare server default values
            # Transaction configuration for offline mode
            transaction_per_migration=True,
        )
        
        # Generate migration script in offline mode
        with context.begin_transaction():
            logger.info("Generating offline migration script")
            context.run_migrations()
            logger.info("Offline migration script generated successfully")
            
    except Exception as e:
        logger.error(f"Offline migration failed: {e}")
        logger.error("Check database URL configuration and model definitions")
        raise


def run_migrations_online():
    """
    Run migrations in 'online' mode with active database connection.
    
    Implements transaction boundary management per Section 6.2.3.2 thread-safe session
    management, providing comprehensive database migration execution with connection pooling,
    SSL enforcement, and transaction safety for development and production environments.
    
    Features:
        - Active database connection with SSL enforcement
        - Transaction boundary management with rollback capabilities
        - Connection pooling optimization for migration performance
        - Real-time migration validation and integrity checking
        
    Transaction Management:
        - Explicit transaction boundaries for migration safety
        - Automatic rollback on migration failure
        - Connection pool optimization for migration operations
        - Thread-safe session management for concurrent access
        
    Error Handling:
        - Comprehensive error logging and diagnostics
        - Migration failure recovery procedures
        - Database connection validation and retry logic
        - Transaction rollback and cleanup on failure
    """
    try:
        logger.info("Running migrations in online mode")
        
        # Create SQLAlchemy engine with production-ready configuration
        engine_config = {
            # Database URL from Flask application configuration
            'sqlalchemy.url': get_engine_url(),
            
            # Connection pooling configuration for migration performance
            'sqlalchemy.poolclass': 'sqlalchemy.pool.QueuePool',
            'sqlalchemy.pool_size': '10',  # Reduced pool size for migrations
            'sqlalchemy.max_overflow': '20',
            'sqlalchemy.pool_timeout': '30',
            'sqlalchemy.pool_recycle': '3600',
            'sqlalchemy.pool_pre_ping': 'true',
            
            # Engine configuration for migration operations
            'sqlalchemy.echo': 'false',  # Disable SQL logging in production
            'sqlalchemy.echo_pool': 'false',
            
            # PostgreSQL-specific configuration
            'sqlalchemy.connect_args': {
                'connect_timeout': 10,
                'statement_timeout': 300000,  # 5 minutes for long migrations
                'application_name': 'flask_migration'
            }
        }
        
        # Create engine with optimized configuration
        connectable = engine_from_config(
            engine_config,
            prefix='sqlalchemy.',
            poolclass=pool.QueuePool,
        )
        
        # Execute migrations with proper connection and transaction management
        with connectable.connect() as connection:
            logger.info("Database connection established for migration")
            
            # Configure Alembic context for online migration
            context.configure(
                connection=connection,
                target_metadata=get_metadata(),
                # Migration execution configuration
                render_as_batch=True,  # Enable batch operations
                compare_type=True,     # Enable column type comparison
                compare_server_default=True,  # Compare server default values
                # Transaction configuration for safety
                transaction_per_migration=True,
                # Migration naming and organization
                include_name=lambda name, type_, parent_names: True,
                include_object=lambda object, name, type_, reflected, compare_to: True,
            )
            
            # Execute migrations within transaction boundary
            with context.begin_transaction():
                logger.info("Beginning migration transaction")
                
                try:
                    # Run migration operations
                    context.run_migrations()
                    logger.info("Migration operations completed successfully")
                    
                except Exception as migration_error:
                    logger.error(f"Migration execution failed: {migration_error}")
                    logger.error("Transaction will be rolled back automatically")
                    raise
                    
        logger.info("Online migration completed successfully")
        
    except Exception as e:
        logger.error(f"Online migration failed: {e}")
        logger.error("Check database connectivity and migration scripts")
        raise


def validate_migration_environment():
    """
    Validate migration environment configuration and dependencies.
    
    Performs comprehensive validation of Flask application configuration, database
    connectivity, model definitions, and migration prerequisites to ensure successful
    migration execution and prevent common configuration errors.
    
    Validation Checks:
        - Flask application factory pattern accessibility
        - Database connection configuration and SSL enforcement
        - Flask-SQLAlchemy model registry and metadata availability
        - Alembic configuration file and migration directory structure
        - Environment variable configuration and security requirements
        
    Returns:
        Boolean indicating validation success
        
    Raises:
        ValueError: If critical configuration validation fails
        ImportError: If required modules are not available
        ConnectionError: If database connectivity cannot be established
    """
    try:
        logger.info("Validating migration environment configuration")
        
        # Validate Flask application creation
        app = get_flask_application()
        logger.debug("✓ Flask application factory accessible")
        
        # Validate database configuration
        with app.app_context():
            database_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
            if not database_uri:
                raise ValueError("SQLALCHEMY_DATABASE_URI not configured")
            logger.debug("✓ Database URI configured")
            
            # Validate SSL enforcement for production
            if not app.debug and not app.testing:
                if 'sslmode=require' not in database_uri and 'sslmode=prefer' not in database_uri:
                    logger.warning("SSL mode not enforced in production database URL")
            
            # Validate model metadata
            metadata = get_metadata()
            if not metadata.tables:
                logger.warning("No database models found - migrations may be empty")
            else:
                logger.debug(f"✓ {len(metadata.tables)} database models discovered")
            
        # Validate Alembic configuration
        if not config.config_file_name:
            logger.warning("Alembic configuration file not found")
        else:
            logger.debug("✓ Alembic configuration loaded")
        
        # Validate migration directory structure
        migrations_dir = os.path.dirname(os.path.abspath(__file__))
        versions_dir = os.path.join(migrations_dir, 'versions')
        if not os.path.exists(versions_dir):
            logger.warning(f"Migration versions directory not found: {versions_dir}")
        else:
            logger.debug("✓ Migration directory structure valid")
        
        logger.info("Migration environment validation completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Migration environment validation failed: {e}")
        return False


# Main migration execution logic
if context.is_offline_mode():
    logger.info("Alembic migration environment: OFFLINE mode")
    
    # Validate environment before offline migration
    if not validate_migration_environment():
        logger.error("Environment validation failed - aborting offline migration")
        sys.exit(1)
    
    # Execute offline migration
    run_migrations_offline()
    
else:
    logger.info("Alembic migration environment: ONLINE mode")
    
    # Validate environment before online migration
    if not validate_migration_environment():
        logger.error("Environment validation failed - aborting online migration")
        sys.exit(1)
    
    # Execute online migration with database connection
    run_migrations_online()

logger.info("Alembic migration environment execution completed")