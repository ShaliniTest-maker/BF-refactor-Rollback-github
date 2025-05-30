"""
Alembic Environment Configuration for Flask-SQLAlchemy Integration

This module provides comprehensive Alembic environment configuration that enables
Flask application context integration, automatic model metadata discovery from
Flask-SQLAlchemy 3.1.1, transaction boundary management, and offline migration
support for production deployment scenarios.

Key Features:
- Flask application factory pattern integration for migration context
- Automatic Flask-SQLAlchemy model discovery and metadata access
- Transaction management with proper commit/rollback handling
- Online and offline migration execution modes
- Production-ready database connection management
- Comprehensive error handling and logging

Architecture Integration:
- Section 4.4.1.3: Flask-Migrate CLI configuration
- Section 4.4.1.1: Model definition standards and metadata access
- Section 6.2.3.2: Thread-safe session management and connection handling
- Section 4.4.1.5: Production migration standards and offline support
"""

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.engine import Connection

# Add the application root directory to the Python path for imports
current_dir = Path(__file__).parent
app_root = current_dir.parent
sys.path.insert(0, str(app_root))

# Import Flask application and database components
# This import structure supports the Flask application factory pattern
try:
    from app import create_app
    from models import db
    from config import Config
except ImportError as e:
    # Enhanced error handling for missing dependencies
    print(f"ERROR: Unable to import Flask application components: {e}")
    print("Ensure app.py, models/__init__.py, and config.py exist and are properly configured.")
    sys.exit(1)

# Alembic Config object for accessing configuration values
config = context.config

# Configure logging from alembic.ini if available
# This enables comprehensive migration operation tracking
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Logger for migration operations
logger = logging.getLogger('alembic.env')


def get_flask_app():
    """
    Create and configure Flask application instance for migration context.
    
    This function implements the Flask application factory pattern integration
    required for accessing Flask-SQLAlchemy metadata during migrations.
    
    Returns:
        Flask: Configured Flask application instance with database initialization
        
    Raises:
        RuntimeError: If application creation or database initialization fails
    """
    try:
        # Create Flask application using factory pattern
        # Configuration is loaded from environment variables via config.py
        app = create_app()
        
        # Ensure application context is available for database operations
        if not app:
            raise RuntimeError("Flask application factory returned None")
            
        logger.info("Flask application created successfully for migration context")
        return app
        
    except Exception as e:
        logger.error(f"Failed to create Flask application: {e}")
        raise RuntimeError(f"Flask application creation failed: {e}")


def get_database_url():
    """
    Retrieve database URL from Flask configuration or environment variables.
    
    This function supports multiple configuration sources following Flask
    configuration management patterns and environment variable precedence.
    
    Returns:
        str: PostgreSQL database connection URL
        
    Raises:
        ValueError: If no valid database URL is found
    """
    # Try Flask application configuration first
    try:
        app = get_flask_app()
        with app.app_context():
            db_url = app.config.get('SQLALCHEMY_DATABASE_URI')
            if db_url:
                logger.info("Database URL retrieved from Flask configuration")
                return db_url
    except Exception as e:
        logger.warning(f"Unable to get database URL from Flask config: {e}")
    
    # Fallback to direct environment variable access
    db_url = os.environ.get('SQLALCHEMY_DATABASE_URI') or os.environ.get('DATABASE_URL')
    if db_url:
        logger.info("Database URL retrieved from environment variables")
        return db_url
    
    # Final fallback for development environment
    default_url = 'postgresql://localhost/flask_db'
    logger.warning(f"No database URL found, using default: {default_url}")
    return default_url


def get_metadata():
    """
    Retrieve Flask-SQLAlchemy metadata for automatic model discovery.
    
    This function provides access to all registered SQLAlchemy models through
    Flask-SQLAlchemy's declarative metadata, enabling automatic migration
    generation based on model definitions.
    
    Returns:
        MetaData: SQLAlchemy metadata containing all model definitions
        
    Raises:
        RuntimeError: If metadata retrieval fails
    """
    try:
        app = get_flask_app()
        with app.app_context():
            # Access Flask-SQLAlchemy metadata containing all model definitions
            # This enables automatic migration generation for all registered models
            metadata = db.metadata
            
            if not metadata:
                raise RuntimeError("Flask-SQLAlchemy metadata is None")
            
            # Log discovered models for debugging
            table_names = list(metadata.tables.keys())
            logger.info(f"Discovered {len(table_names)} tables in metadata: {table_names}")
            
            return metadata
            
    except Exception as e:
        logger.error(f"Failed to retrieve Flask-SQLAlchemy metadata: {e}")
        raise RuntimeError(f"Metadata retrieval failed: {e}")


# Set target metadata for Alembic autogeneration
# This connects Alembic to Flask-SQLAlchemy model definitions
target_metadata = get_metadata()


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode for production deployment scenarios.
    
    This configures the context with the database URL only, without creating
    an actual database connection. This mode is ideal for production environments
    where migration SQL scripts need to be generated without active database
    connections.
    
    Features:
    - SQL script generation without database connection
    - Production deployment compatibility
    - Enhanced error handling and validation
    - Comprehensive logging for audit trails
    """
    try:
        # Retrieve database URL for offline script generation
        url = get_database_url()
        
        # Configure Alembic context for offline execution
        context.configure(
            url=url,
            target_metadata=target_metadata,
            literal_binds=True,
            dialect_opts={"paramstyle": "named"},
            # Enable comprehensive comparison options for accurate migrations
            compare_type=True,
            compare_server_default=True,
            # Include schema name in generated SQL for multi-schema environments
            include_schemas=True,
            # Render item for better SQL script readability
            render_item=render_item,
        )
        
        logger.info("Starting offline migration execution")
        
        with context.begin_transaction():
            context.run_migrations()
            
        logger.info("Offline migration completed successfully")
        
    except Exception as e:
        logger.error(f"Offline migration failed: {e}")
        raise


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode with active database connection.
    
    This mode creates an actual database connection for executing migrations
    directly against the database. Includes comprehensive transaction management,
    connection pooling optimization, and error handling for production reliability.
    
    Features:
    - Direct database connection and execution
    - Transaction boundary management
    - Connection pool optimization
    - Comprehensive error handling and rollback
    - Flask application context integration
    """
    # Create Flask application context for database operations
    app = get_flask_app()
    
    with app.app_context():
        try:
            # Configure database connection with optimized settings
            # These settings align with Flask-SQLAlchemy connection pool configuration
            configuration = config.get_section(config.config_ini_section)
            configuration['sqlalchemy.url'] = get_database_url()
            
            # Production-optimized connection settings
            # Pool configuration matches Flask-SQLAlchemy production settings
            configuration.setdefault('sqlalchemy.pool_size', '20')
            configuration.setdefault('sqlalchemy.max_overflow', '30')
            configuration.setdefault('sqlalchemy.pool_timeout', '30')
            configuration.setdefault('sqlalchemy.pool_recycle', '3600')
            configuration.setdefault('sqlalchemy.pool_pre_ping', 'true')
            
            # Create optimized database engine
            connectable = engine_from_config(
                configuration,
                prefix="sqlalchemy.",
                poolclass=pool.NullPool,  # Let Flask-SQLAlchemy handle connection pooling
            )
            
            logger.info("Establishing database connection for online migration")
            
            with connectable.connect() as connection:
                # Configure Alembic context with active database connection
                context.configure(
                    connection=connection,
                    target_metadata=target_metadata,
                    # Enhanced comparison options for accurate migration detection
                    compare_type=True,
                    compare_server_default=True,
                    # Include schema information for multi-schema support
                    include_schemas=True,
                    # Custom rendering for better migration script quality
                    render_item=render_item,
                    # Transaction management options
                    transaction_per_migration=True,
                )
                
                logger.info("Starting online migration execution")
                
                # Execute migrations within transaction boundary
                with context.begin_transaction():
                    context.run_migrations()
                    
                logger.info("Online migration completed successfully")
                
        except Exception as e:
            logger.error(f"Online migration failed: {e}")
            # Ensure proper cleanup and error propagation
            raise


def render_item(type_, obj, autogen_context):
    """
    Custom rendering function for enhanced migration script generation.
    
    This function provides custom rendering logic for Alembic autogeneration,
    improving the quality and readability of generated migration scripts while
    supporting PostgreSQL-specific features and data types.
    
    Args:
        type_ (str): Type of object being rendered
        obj: SQLAlchemy object to render
        autogen_context: Alembic autogeneration context
        
    Returns:
        str or None: Custom rendering string or None for default behavior
    """
    # Enhanced rendering for PostgreSQL-specific types
    if type_ == "type" and hasattr(obj, "python_type"):
        # Support for PostgreSQL-specific data types
        if obj.python_type.__name__ == "UUID":
            return "postgresql.UUID()"
        elif obj.python_type.__name__ == "JSONB":
            return "postgresql.JSONB()"
    
    # Support for custom column types used in the application
    if type_ == "column" and hasattr(obj, "type"):
        # Handle SQLAlchemy-Utils EncryptedType rendering
        if "EncryptedType" in str(obj.type):
            return f"sa.String({obj.type.length})"  # Render as String for migration
    
    # Use default rendering for all other cases
    return None


def validate_migration_environment():
    """
    Validate migration environment configuration and dependencies.
    
    This function performs comprehensive validation of the migration environment
    to ensure all required components are available and properly configured
    before migration execution.
    
    Raises:
        RuntimeError: If validation fails
    """
    try:
        # Validate Flask application availability
        app = get_flask_app()
        if not app:
            raise RuntimeError("Flask application is not available")
        
        # Validate database configuration
        db_url = get_database_url()
        if not db_url:
            raise RuntimeError("Database URL is not configured")
        
        # Validate metadata availability
        metadata = get_metadata()
        if not metadata or not metadata.tables:
            logger.warning("No tables found in metadata - this may be expected for initial migration")
        
        # Validate Flask-SQLAlchemy integration
        with app.app_context():
            if not hasattr(db, 'engine'):
                raise RuntimeError("Flask-SQLAlchemy database engine is not initialized")
        
        logger.info("Migration environment validation completed successfully")
        
    except Exception as e:
        logger.error(f"Migration environment validation failed: {e}")
        raise RuntimeError(f"Environment validation failed: {e}")


# Main execution logic with comprehensive validation and error handling
if context.is_offline_mode():
    logger.info("Running migrations in OFFLINE mode")
    validate_migration_environment()
    run_migrations_offline()
else:
    logger.info("Running migrations in ONLINE mode")
    validate_migration_environment()
    run_migrations_online()


# Additional utility functions for migration management
def get_current_revision():
    """
    Get the current database revision for migration status reporting.
    
    Returns:
        str: Current database revision identifier
    """
    try:
        app = get_flask_app()
        with app.app_context():
            with db.engine.connect() as connection:
                context.configure(connection=connection, target_metadata=target_metadata)
                return context.get_current_revision()
    except Exception as e:
        logger.error(f"Failed to get current revision: {e}")
        return None


def validate_migration_integrity():
    """
    Validate migration integrity and consistency.
    
    This function can be called after migrations to ensure database schema
    matches the expected model definitions and migration history is consistent.
    
    Returns:
        bool: True if validation passes, False otherwise
    """
    try:
        app = get_flask_app()
        with app.app_context():
            # Validate metadata consistency
            metadata = get_metadata()
            
            # Check for model-database schema alignment
            with db.engine.connect() as connection:
                # This would contain actual validation logic
                # For now, we perform basic checks
                tables_in_db = db.engine.table_names()
                tables_in_metadata = list(metadata.tables.keys())
                
                missing_tables = set(tables_in_metadata) - set(tables_in_db)
                extra_tables = set(tables_in_db) - set(tables_in_metadata)
                
                if missing_tables:
                    logger.warning(f"Tables in metadata but not in database: {missing_tables}")
                
                if extra_tables:
                    logger.warning(f"Tables in database but not in metadata: {extra_tables}")
                
                return len(missing_tables) == 0
                
    except Exception as e:
        logger.error(f"Migration integrity validation failed: {e}")
        return False